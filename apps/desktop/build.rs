//! macOS: embed `macos/Info.plist` in the executable (the `__TEXT,__info_plist` section), so
//! that the unbundled binary carries the camera and microphone usage strings. macOS ends a
//! process that asks for the camera or the microphone without them. An app bundle's own
//! `Info.plist` (packaging) takes the same keys from the same file.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=macos/Info.plist");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
        println!(
            "cargo:rustc-link-arg-bins=-Wl,-sectcreate,__TEXT,__info_plist,{dir}/macos/Info.plist"
        );
    }
}
