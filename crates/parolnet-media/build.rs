//! With the `vpx` feature: links libvpx (BSD-3-Clause) for the VP8 decoder (hand-written
//! binding, `src/vp8/dec.rs`) and builds the encoder shim `src/vp8/vp8enc.c` against the same
//! libvpx's headers. Without it this script does nothing.
//!
//! `VPX_LIB_DIR` (+ optional `VPX_STATIC=1`, and `VPX_INCLUDE_DIR` for the shim) overrides
//! discovery. Otherwise pkg-config on macOS / Linux (Homebrew `libvpx`, apt `libvpx-dev`) and
//! vcpkg on Windows (`vcpkg install libvpx:x64-windows-static-md`, or `arm64-windows-static-md`).

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "vpx")]
    vpx::build();
}

#[cfg(feature = "vpx")]
mod vpx {
    use std::path::PathBuf;

    pub fn build() {
        println!("cargo:rerun-if-env-changed=VPX_LIB_DIR");
        println!("cargo:rerun-if-env-changed=VPX_STATIC");
        println!("cargo:rerun-if-env-changed=VPX_INCLUDE_DIR");
        println!("cargo:rerun-if-changed=src/vp8/vp8enc.c");

        let includes = link_libvpx();
        let mut shim = cc::Build::new();
        shim.file("src/vp8/vp8enc.c").warnings(true);
        for dir in includes {
            shim.include(dir);
        }
        shim.compile("pn_vp8enc");
    }

    /// Emit the link flags for libvpx; returns the include directories for the shim.
    fn link_libvpx() -> Vec<PathBuf> {
        if let Ok(dir) = std::env::var("VPX_LIB_DIR") {
            println!("cargo:rustc-link-search=native={dir}");
            let kind = if std::env::var("VPX_STATIC").is_ok_and(|v| v == "1") {
                "static"
            } else {
                "dylib"
            };
            println!("cargo:rustc-link-lib={kind}=vpx");
            return std::env::var("VPX_INCLUDE_DIR")
                .map(|d| vec![PathBuf::from(d)])
                .unwrap_or_default();
        }

        // The target's OS, not the build host's (they differ when cross-checking).
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
            return match vcpkg::Config::new().find_package("libvpx") {
                Ok(lib) => lib.include_paths,
                Err(err) => panic!(
                    "libvpx not found ({err}): `vcpkg install libvpx:<triplet>-static-md` or set \
                 VPX_LIB_DIR"
                ),
            };
        }

        match pkg_config::Config::new().probe("vpx") {
            Ok(lib) => lib.include_paths,
            Err(err) => panic!(
                "libvpx not found ({err}): install it (brew install libvpx / apt install libvpx-dev) \
             or set VPX_LIB_DIR"
            ),
        }
    }
}
