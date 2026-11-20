//! The spike window: one video tile and a status line.
//!
//! macOS draws an NV12 `CVPixelBuffer` with `gpui::surface()` (sampled from its IOSurface on
//! the GPU). Windows and Linux draw a BGRA `RenderImage` with `img()` and drop the previous
//! one from the sprite atlas every frame (the approach Zed uses for remote video off macOS).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use gpui::{
    App, Bounds, Context, ImageSource, IntoElement, ObjectFit, Render, RenderImage, Window,
    WindowBounds, WindowOptions, div, img, prelude::*, px, rgb, size,
};
use gpui_component::Root;

use crate::frame::{FrameSlot, Presentable};
use crate::receiver::Stats;

enum Current {
    #[cfg(target_os = "macos")]
    Surface(objc2_core_foundation::CFRetained<objc2_core_video::CVPixelBuffer>),
    Image(Arc<RenderImage>),
}

pub struct VideoView {
    slot: FrameSlot,
    stats: Arc<Stats>,
    current: Option<Current>,
    seen_sequence: u64,
    presented: u64,
    first_frame_at: Option<Instant>,
    exit_after: Option<Duration>,
    path: &'static str,
}

impl VideoView {
    pub(crate) fn new(
        slot: FrameSlot,
        stats: Arc<Stats>,
        exit_after: Option<Duration>,
        cx: &mut Context<Self>,
    ) -> Self {
        // Poll the slot at ~120 Hz and repaint only when a new picture arrived. Decode never
        // touches this thread.
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(8))
                    .await;
                if this.update(cx, |view, cx| view.tick(cx)).is_err() {
                    break;
                }
            }
        })
        .detach();
        Self {
            slot,
            stats,
            current: None,
            seen_sequence: 0,
            presented: 0,
            first_frame_at: None,
            exit_after,
            path: "none yet",
        }
    }

    fn tick(&mut self, cx: &mut Context<Self>) {
        let (sequence, ..) = self.slot.info();
        if sequence != self.seen_sequence {
            self.seen_sequence = sequence;
            cx.notify();
        }
        if let (Some(first), Some(limit)) = (self.first_frame_at, self.exit_after)
            && first.elapsed() >= limit
        {
            println!(
                "spike-window presented={} decoded={} path={}",
                self.presented,
                self.stats.decoded.load(Ordering::Relaxed),
                self.path
            );
            cx.quit();
        }
    }

    fn take_frame(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(frame) = self.slot.take() else {
            return;
        };
        let next = match frame {
            #[cfg(target_os = "macos")]
            Presentable::Surface(buffer) => {
                self.path = "surface (CVPixelBuffer NV12)";
                Current::Surface(buffer.0)
            }
            Presentable::Bgra {
                width,
                height,
                pixels,
            } => {
                self.path = "RenderImage (BGRA)";
                let Some(buffer) = image::RgbaImage::from_raw(width, height, pixels) else {
                    return;
                };
                Current::Image(Arc::new(RenderImage::new(vec![image::Frame::new(buffer)])))
            }
        };
        if let Some(Current::Image(old)) = self.current.replace(next) {
            cx.drop_image(old, Some(window));
        }
        self.presented += 1;
        if self.first_frame_at.is_none() {
            self.first_frame_at = Some(Instant::now());
            println!("spike-window first-frame path={}", self.path);
        }
    }
}

impl Render for VideoView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.take_frame(window, cx);
        let (_, status, width, height) = self.slot.info();
        let tile = match &self.current {
            #[cfg(target_os = "macos")]
            Some(Current::Surface(buffer)) => gpui::surface(buffer.clone())
                .object_fit(ObjectFit::Contain)
                .size_full()
                .into_any_element(),
            Some(Current::Image(image)) => img(ImageSource::Render(image.clone()))
                .object_fit(ObjectFit::Contain)
                .size_full()
                .into_any_element(),
            None => div()
                .size_full()
                .flex()
                .items_center()
                .justify_center()
                .text_color(rgb(0x9a9a9a))
                .child("no video yet")
                .into_any_element(),
        };
        let line = format!(
            "{status} | {width}x{height} | decoded {} | presented {} | {}",
            self.stats.decoded.load(Ordering::Relaxed),
            self.presented,
            self.path
        );
        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(rgb(0x101010))
            .child(div().flex_1().min_h_0().child(tile))
            .child(
                div()
                    .px_3()
                    .py_1()
                    .bg(rgb(0x202020))
                    .text_color(rgb(0xe0e0e0))
                    .child(gpui_component::label::Label::new(line)),
            )
    }
}

pub fn run(slot: FrameSlot, stats: Arc<Stats>, exit_after: Option<Duration>) {
    gpui_platform::application().run(move |cx: &mut App| {
        gpui_component::init(cx);
        let bounds = Bounds::centered(None, size(px(960.), px(600.)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                ..Default::default()
            },
            move |window, cx| {
                let view = cx.new(|cx| VideoView::new(slot, stats, exit_after, cx));
                cx.new(|cx| Root::new(view, window, cx))
            },
        )
        .expect("open the spike window");
        cx.on_window_closed(|cx, _| cx.quit()).detach();
        cx.activate(true);
    });
}
