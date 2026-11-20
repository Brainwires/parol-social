//! Links libvpx (BSD-3-Clause), the VP8 decoder.
//!
//! `VPX_LIB_DIR` (+ optional `VPX_STATIC=1`) overrides discovery. Otherwise pkg-config on
//! macOS / Linux (Homebrew `libvpx`, apt `libvpx-dev`) and vcpkg on Windows
//! (`vcpkg install libvpx:x64-windows-static-md`, or `arm64-windows-static-md`).

fn main() {
    println!("cargo:rerun-if-env-changed=VPX_LIB_DIR");
    println!("cargo:rerun-if-env-changed=VPX_STATIC");
    if let Ok(dir) = std::env::var("VPX_LIB_DIR") {
        println!("cargo:rustc-link-search=native={dir}");
        let kind = if std::env::var("VPX_STATIC").is_ok_and(|v| v == "1") {
            "static"
        } else {
            "dylib"
        };
        println!("cargo:rustc-link-lib={kind}=vpx");
        return;
    }

    // The target's OS, not the build host's (they differ when cross-checking).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        if let Err(err) = vcpkg::Config::new().find_package("libvpx") {
            panic!(
                "libvpx not found ({err}): `vcpkg install libvpx:<triplet>-static-md` or set \
                 VPX_LIB_DIR"
            );
        }
        return;
    }

    if let Err(err) = pkg_config::Config::new().probe("vpx") {
        panic!(
            "libvpx not found ({err}): install it (brew install libvpx / apt install libvpx-dev) \
             or set VPX_LIB_DIR"
        );
    }
}
