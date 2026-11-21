//! A synthetic camera: colour bars, a moving box and a frame counter, drawn straight into
//! I420. Calls send it when there is no camera (CI has none), and the bot's IVF is made of it.

use crate::frame::I420Frame;

/// BT.601 limited-range YUV of the bars (white, yellow, cyan, green, magenta, red, blue).
const BARS: [(u8, u8, u8); 7] = [
    (180, 128, 128),
    (162, 44, 142),
    (131, 156, 44),
    (112, 72, 58),
    (84, 184, 198),
    (65, 100, 212),
    (35, 212, 114),
];

/// 3x5 digit glyphs, one bit per pixel, rows top to bottom.
const DIGITS: [[u8; 5]; 10] = [
    [7, 5, 5, 5, 7],
    [2, 6, 2, 2, 7],
    [7, 1, 7, 4, 7],
    [7, 1, 7, 1, 7],
    [5, 5, 7, 1, 1],
    [7, 4, 7, 1, 7],
    [7, 4, 7, 5, 7],
    [7, 1, 1, 1, 1],
    [7, 5, 7, 5, 7],
    [7, 5, 7, 1, 7],
];

pub struct TestPattern {
    width: u32,
    height: u32,
    n: u64,
}

impl TestPattern {
    /// `width` and `height` must be even.
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            n: 0,
        }
    }

    pub fn next_frame(&mut self) -> I420Frame {
        let (w, h) = (self.width as usize, self.height as usize);
        let mut f = I420Frame::new(self.width, self.height);
        let bar_w = w.div_ceil(BARS.len());
        {
            let y = f.plane_mut(0);
            for row in 0..h {
                for col in 0..w {
                    y[row * w + col] = BARS[(col / bar_w).min(BARS.len() - 1)].0;
                }
            }
        }
        for (plane, pick) in [(1usize, 1usize), (2, 2)] {
            let (cw, ch) = (w / 2, h / 2);
            let p = f.plane_mut(plane);
            for row in 0..ch {
                for col in 0..cw {
                    let (_, u, v) = BARS[((col * 2) / bar_w).min(BARS.len() - 1)];
                    p[row * cw + col] = if pick == 1 { u } else { v };
                }
            }
        }
        // A dark box sliding left to right in the lower third.
        let size = (h / 4).max(8) & !1;
        let span = w + size;
        let x0 = ((self.n as usize * 4) % span) as isize - size as isize;
        let y0 = (h * 2 / 3).min(h - size) & !1;
        self.fill_rect(&mut f, x0, y0 as isize, size, size, (16, 128, 128));
        // The frame counter, top left, on a white plate.
        let scale = (h / 60).max(2);
        let digits = format!("{:06}", self.n % 1_000_000);
        let plate_w = digits.len() * 4 * scale + 2 * scale;
        self.fill_rect(&mut f, 0, 0, plate_w, 7 * scale, (235, 128, 128));
        for (i, d) in digits.bytes().enumerate() {
            let glyph = DIGITS[(d - b'0') as usize];
            for (gy, bits) in glyph.iter().enumerate() {
                for gx in 0..3 {
                    if bits & (4 >> gx) != 0 {
                        self.fill_rect(
                            &mut f,
                            ((1 + i * 4 + gx) * scale) as isize,
                            ((1 + gy) * scale) as isize,
                            scale,
                            scale,
                            (16, 128, 128),
                        );
                    }
                }
            }
        }
        self.n += 1;
        f
    }

    fn fill_rect(
        &self,
        f: &mut I420Frame,
        x0: isize,
        y0: isize,
        rw: usize,
        rh: usize,
        (yv, uv, vv): (u8, u8, u8),
    ) {
        let (w, h) = (self.width as isize, self.height as isize);
        let x1 = (x0 + rw as isize).min(w);
        let y1 = (y0 + rh as isize).min(h);
        let (x0, y0) = (x0.max(0), y0.max(0));
        if x0 >= x1 || y0 >= y1 {
            return;
        }
        let y = f.plane_mut(0);
        for row in y0..y1 {
            for col in x0..x1 {
                y[(row * w + col) as usize] = yv;
            }
        }
        let cw = w / 2;
        for (plane, value) in [(1, uv), (2, vv)] {
            let p = f.plane_mut(plane);
            for row in (y0 / 2)..(y1 / 2) {
                for col in (x0 / 2)..(x1 / 2) {
                    p[(row * cw + col) as usize] = value;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_change_and_have_bars() {
        let mut p = TestPattern::new(320, 180);
        let a = p.next_frame();
        let b = p.next_frame();
        assert_ne!(a.plane(0), b.plane(0), "the counter and the box move");
        // The bottom-right corner is the last (blue) bar.
        let y = a.plane(0);
        assert_eq!(y[179 * 320 + 319], BARS[6].0);
    }
}
