//! Microphone and speakers through `cpal` (CoreAudio, WASAPI, ALSA).
//!
//! The device callbacks run on the operating system's real-time audio threads. They do three
//! things only: convert the device's samples to or from mono `f32`, move them through a
//! wait-free single-producer single-consumer ring ([`rtrb`]), and store a few atomics. They
//! never allocate, lock, log or block; resampling, echo cancellation and the codec run on the
//! call's own audio thread, which talks to the rings through [`Microphone`] and [`Speaker`].
//!
//! A device that disappears mid-call (unplugged, the default changed under a pinned device)
//! is reported by `cpal`'s error callback into an atomic; the next [`AudioSource::read`] or
//! [`AudioSink::write`] returns an error and the call drops the device. Nothing panics.

use std::str::FromStr as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::time::Duration;

use cpal::traits::{DeviceTrait as _, HostTrait as _, StreamTrait as _};
use cpal::{FromSample, SampleFormat, SizedSample};

use crate::MediaError;
use crate::source::{AudioSink, AudioSource, DeviceInfo};

/// How long to wait for the device thread to open a stream.
const OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// State shared between a stream's callbacks and its owner.
#[derive(Default)]
struct Shared {
    /// The device reported an error that ends the stream.
    failed: AtomicBool,
    /// Samples the ring could not take (input) or did not have (output).
    xruns: AtomicU32,
    /// The device-side latency the last callback reported, in microseconds.
    latency_us: AtomicU32,
    /// The largest callback so far, in sample times.
    max_callback: AtomicUsize,
    /// Tells the thread that owns the stream to drop it.
    stop: AtomicBool,
}

fn device_error(e: cpal::Error) -> MediaError {
    match e.kind() {
        cpal::ErrorKind::PermissionDenied => MediaError::PermissionDenied,
        cpal::ErrorKind::DeviceNotAvailable | cpal::ErrorKind::HostUnavailable => {
            MediaError::NoDevice
        }
        _ => MediaError::Device(e.to_string()),
    }
}

/// Whether a stream error ends the stream (a reroute of the default device does not).
fn is_fatal(e: &cpal::Error) -> bool {
    !matches!(
        e.kind(),
        cpal::ErrorKind::DeviceChanged | cpal::ErrorKind::RealtimeDenied
    )
}

fn list(devices: impl Iterator<Item = cpal::Device>) -> Vec<DeviceInfo> {
    devices
        .filter_map(|d| {
            let id = d.id().ok()?.to_string();
            let name = d
                .description()
                .map(|desc| desc.name().to_owned())
                .unwrap_or_else(|_| id.clone());
            Some(DeviceInfo { id, name })
        })
        .collect()
}

/// The microphones (and other inputs) the system has. Empty when there are none or the audio
/// host is unavailable.
pub fn input_devices() -> Vec<DeviceInfo> {
    cpal::default_host()
        .input_devices()
        .map(|d| list(d))
        .unwrap_or_default()
}

/// The speakers (and other outputs) the system has.
pub fn output_devices() -> Vec<DeviceInfo> {
    cpal::default_host()
        .output_devices()
        .map(|d| list(d))
        .unwrap_or_default()
}

/// The device with `id` (as [`DeviceInfo::id`]), or the system default for `None`.
fn find(id: Option<&str>, input: bool) -> Result<cpal::Device, MediaError> {
    let host = cpal::default_host();
    let device = match id {
        Some(id) => {
            let id = cpal::DeviceId::from_str(id).map_err(|_| MediaError::NoDevice)?;
            host.device_by_id(&id)
        }
        None if input => host.default_input_device(),
        None => host.default_output_device(),
    };
    device.ok_or(MediaError::NoDevice)
}

/// Build the stream on a thread of its own and keep it there until `shared.stop`: a `cpal`
/// stream is not `Send` on every host, and this way its owner need not be either.
fn own_stream<F>(name: &str, shared: Arc<Shared>, build: F) -> Result<(), MediaError>
where
    F: FnOnce() -> Result<cpal::Stream, MediaError> + Send + 'static,
{
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<(), MediaError>>(1);
    std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let stream = match build().and_then(|s| s.play().map(|()| s).map_err(device_error)) {
                Ok(stream) => {
                    let _ = ready_tx.send(Ok(()));
                    stream
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            while !shared.stop.load(Ordering::Relaxed) {
                std::thread::park_timeout(Duration::from_millis(200));
            }
            drop(stream);
        })
        .map_err(|e| MediaError::Device(format!("audio thread: {e}")))?;
    match ready_rx.recv_timeout(OPEN_TIMEOUT) {
        Ok(result) => result,
        Err(_) => Err(MediaError::Device(
            "the audio device did not open in time".into(),
        )),
    }
}

/// A microphone: mono samples at the device's rate.
pub struct Microphone {
    rx: rtrb::Consumer<f32>,
    rate: u32,
    name: String,
    shared: Arc<Shared>,
}

impl Microphone {
    /// Open the input device with `id`, or the default one. On macOS the first use asks the
    /// user for microphone access.
    pub fn open(id: Option<&str>) -> Result<Self, MediaError> {
        let device = find(id, true)?;
        let name = device
            .description()
            .map(|d| d.name().to_owned())
            .unwrap_or_else(|_| "Microphone".to_owned());
        let supported = device.default_input_config().map_err(device_error)?;
        let rate = supported.sample_rate();
        let channels = usize::from(supported.channels()).max(1);
        let format = supported.sample_format();
        let config = supported.config();
        // Half a second: far more than the audio thread ever leaves unread.
        let (tx, rx) = rtrb::RingBuffer::<f32>::new(rate as usize / 2);
        let shared = Arc::new(Shared::default());
        let cb_shared = shared.clone();
        own_stream("mic-stream", shared.clone(), move || match format {
            SampleFormat::F32 => input_stream::<f32>(&device, config, channels, tx, cb_shared),
            SampleFormat::I16 => input_stream::<i16>(&device, config, channels, tx, cb_shared),
            SampleFormat::U16 => input_stream::<u16>(&device, config, channels, tx, cb_shared),
            SampleFormat::I32 => input_stream::<i32>(&device, config, channels, tx, cb_shared),
            other => Err(MediaError::Format(format!(
                "microphone sample format {other:?}"
            ))),
        })?;
        Ok(Self {
            rx,
            rate,
            name,
            shared,
        })
    }

    /// The device's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Samples lost because the reader was too slow.
    pub fn overruns(&self) -> u32 {
        self.shared.xruns.load(Ordering::Relaxed)
    }
}

fn input_stream<T>(
    device: &cpal::Device,
    config: cpal::StreamConfig,
    channels: usize,
    mut tx: rtrb::Producer<f32>,
    shared: Arc<Shared>,
) -> Result<cpal::Stream, MediaError>
where
    T: SizedSample,
    f32: FromSample<T>,
{
    let err_shared = shared.clone();
    device
        .build_input_stream::<T, _, _>(
            config,
            move |data: &[T], info: &cpal::InputCallbackInfo| {
                // Real-time thread: no allocation, no locks.
                let ts = info.timestamp();
                let latency = ts.callback.duration_since(ts.capture);
                shared
                    .latency_us
                    .store(latency.as_micros().min(1_000_000) as u32, Ordering::Relaxed);
                let mut lost = 0u32;
                for frame in data.chunks_exact(channels) {
                    let mut sum = 0f32;
                    for &s in frame {
                        sum += f32::from_sample_(s);
                    }
                    if tx.push(sum / channels as f32).is_err() {
                        lost += 1;
                    }
                }
                if lost > 0 {
                    shared.xruns.fetch_add(lost, Ordering::Relaxed);
                }
            },
            move |e| {
                if is_fatal(&e) {
                    err_shared.failed.store(true, Ordering::Relaxed);
                }
            },
            None,
        )
        .map_err(device_error)
}

impl AudioSource for Microphone {
    fn sample_rate(&self) -> u32 {
        self.rate
    }

    fn read(&mut self, out: &mut Vec<f32>) -> Result<(), MediaError> {
        if self.shared.failed.load(Ordering::Relaxed) {
            return Err(MediaError::Device(format!("{} went away", self.name)));
        }
        let n = self.rx.slots();
        if let Ok(chunk) = self.rx.read_chunk(n) {
            let (a, b) = chunk.as_slices();
            out.extend_from_slice(a);
            out.extend_from_slice(b);
            chunk.commit_all();
        }
        Ok(())
    }

    fn latency(&self) -> Duration {
        Duration::from_micros(u64::from(self.shared.latency_us.load(Ordering::Relaxed)))
    }
}

impl Drop for Microphone {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
    }
}

/// Speakers: mono samples at the device's rate, copied to every output channel.
pub struct Speaker {
    tx: rtrb::Producer<f32>,
    capacity: usize,
    rate: u32,
    name: String,
    shared: Arc<Shared>,
}

impl Speaker {
    /// Open the output device with `id`, or the default one.
    pub fn open(id: Option<&str>) -> Result<Self, MediaError> {
        let device = find(id, false)?;
        let name = device
            .description()
            .map(|d| d.name().to_owned())
            .unwrap_or_else(|_| "Speakers".to_owned());
        let supported = device.default_output_config().map_err(device_error)?;
        let rate = supported.sample_rate();
        let channels = usize::from(supported.channels()).max(1);
        let format = supported.sample_format();
        let config = supported.config();
        let capacity = rate as usize / 2;
        let (tx, rx) = rtrb::RingBuffer::<f32>::new(capacity);
        let shared = Arc::new(Shared::default());
        let cb_shared = shared.clone();
        own_stream("speaker-stream", shared.clone(), move || match format {
            SampleFormat::F32 => output_stream::<f32>(&device, config, channels, rx, cb_shared),
            SampleFormat::I16 => output_stream::<i16>(&device, config, channels, rx, cb_shared),
            SampleFormat::U16 => output_stream::<u16>(&device, config, channels, rx, cb_shared),
            SampleFormat::I32 => output_stream::<i32>(&device, config, channels, rx, cb_shared),
            other => Err(MediaError::Format(format!(
                "speaker sample format {other:?}"
            ))),
        })?;
        Ok(Self {
            tx,
            capacity,
            rate,
            name,
            shared,
        })
    }

    /// The device's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Sample times the device played silence because nothing was queued.
    pub fn underruns(&self) -> u32 {
        self.shared.xruns.load(Ordering::Relaxed)
    }
}

fn output_stream<T>(
    device: &cpal::Device,
    config: cpal::StreamConfig,
    channels: usize,
    mut rx: rtrb::Consumer<f32>,
    shared: Arc<Shared>,
) -> Result<cpal::Stream, MediaError>
where
    T: SizedSample + FromSample<f32>,
{
    let err_shared = shared.clone();
    device
        .build_output_stream::<T, _, _>(
            config,
            move |data: &mut [T], info: &cpal::OutputCallbackInfo| {
                // Real-time thread: no allocation, no locks.
                let ts = info.timestamp();
                let latency = ts.playback.duration_since(ts.callback);
                shared
                    .latency_us
                    .store(latency.as_micros().min(1_000_000) as u32, Ordering::Relaxed);
                let frames = data.len() / channels;
                shared.max_callback.fetch_max(frames, Ordering::Relaxed);
                let mut missing = 0u32;
                for frame in data.chunks_exact_mut(channels) {
                    let v = match rx.pop() {
                        Ok(v) => v,
                        Err(_) => {
                            missing += 1;
                            0.0
                        }
                    };
                    let s = T::from_sample_(v);
                    for out in frame {
                        *out = s;
                    }
                }
                if missing > 0 {
                    shared.xruns.fetch_add(missing, Ordering::Relaxed);
                }
            },
            move |e| {
                if is_fatal(&e) {
                    err_shared.failed.store(true, Ordering::Relaxed);
                }
            },
            None,
        )
        .map_err(device_error)
}

impl AudioSink for Speaker {
    fn sample_rate(&self) -> u32 {
        self.rate
    }

    fn queued(&self) -> usize {
        self.capacity.saturating_sub(self.tx.slots())
    }

    /// Enough for two of the device's callbacks plus 10 ms of slack for the audio thread's
    /// own cadence, at least 30 ms and at most 200 ms.
    fn target_queue(&self) -> usize {
        let rate = self.rate as usize;
        let callback = self.shared.max_callback.load(Ordering::Relaxed);
        (2 * callback + rate / 100).clamp(rate * 30 / 1000, rate / 5)
    }

    fn write(&mut self, samples: &[f32]) -> Result<(), MediaError> {
        if self.shared.failed.load(Ordering::Relaxed) {
            return Err(MediaError::Device(format!("{} went away", self.name)));
        }
        let n = samples.len().min(self.tx.slots());
        if let Ok(chunk) = self.tx.write_chunk_uninit(n) {
            let written = chunk.fill_from_iter(samples[..n].iter().copied());
            debug_assert_eq!(written, n);
        }
        Ok(())
    }

    fn latency(&self) -> Duration {
        Duration::from_micros(u64::from(self.shared.latency_us.load(Ordering::Relaxed)))
    }
}

impl Drop for Speaker {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
    }
}
