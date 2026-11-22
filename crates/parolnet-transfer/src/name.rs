//! The offered file name is a string from the other side, not a path (PNP-010 §7.3).

/// Longest name this function returns, in UTF-8 bytes.
const LOCAL_NAME_MAX: usize = 200;
/// Longest extension kept when a name is shortened.
const EXTENSION_MAX: usize = 16;

/// A file name that is safe to create inside a directory of the receiver's choosing, made
/// from the name in an offer:
///
/// - only the last path component is kept (both `/` and `\` separate components);
/// - control characters, the characters Windows forbids (`< > : " | ? *`) and the Unicode
///   direction and invisible formatting characters (which can make `exe.jpg` read as
///   `gpj.exe`) are removed;
/// - leading dots and surrounding white space, and trailing dots, are removed, so the result
///   is never `.`, `..` or a hidden file;
/// - Windows device names (`CON`, `NUL`, `COM1`, …) get a `_` in front;
/// - it is shortened to 200 bytes, keeping a short extension;
/// - when nothing is left the name is `file`.
///
/// The caller still chooses the directory and must not overwrite an existing file.
pub fn sanitize_file_name(offered: &str) -> String {
    let component = offered
        .rsplit(['/', '\\'])
        .find(|part| !part.trim().is_empty())
        .unwrap_or("");
    let cleaned: String = component
        .chars()
        .filter(|c| !c.is_control() && !forbidden(*c))
        .collect();
    let trimmed = cleaned
        .trim()
        .trim_start_matches('.')
        .trim_end_matches(['.', ' '])
        .trim();
    if trimmed.is_empty() {
        return "file".to_owned();
    }
    let mut name = shorten(trimmed);
    let stem = name.split('.').next().unwrap_or("");
    if is_device_name(stem) {
        name.insert(0, '_');
    }
    name
}

fn forbidden(c: char) -> bool {
    matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*')
        || matches!(
            c,
            '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}'
        )
}

fn is_device_name(stem: &str) -> bool {
    let upper = stem.trim().to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (upper.len() == 4
            && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.as_bytes()[3].is_ascii_digit()
            && upper.as_bytes()[3] != b'0')
}

fn cut(s: &str, max: usize) -> &str {
    let mut end = max.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn shorten(name: &str) -> String {
    if name.len() <= LOCAL_NAME_MAX {
        return name.to_owned();
    }
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() && ext.len() <= EXTENSION_MAX => {
            let stem = cut(stem, LOCAL_NAME_MAX - ext.len() - 1).trim_end_matches(['.', ' ']);
            format!("{stem}.{ext}")
        }
        _ => cut(name, LOCAL_NAME_MAX)
            .trim_end_matches(['.', ' '])
            .to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize_file_name as s;

    #[test]
    fn ordinary_names_are_kept() {
        assert_eq!(s("report.pdf"), "report.pdf");
        assert_eq!(s("Отчёт 2026 (final).docx"), "Отчёт 2026 (final).docx");
        assert_eq!(s("archive.tar.gz"), "archive.tar.gz");
    }

    #[test]
    fn paths_become_their_last_component() {
        assert_eq!(s("../../etc/passwd"), "passwd");
        assert_eq!(s("/etc/shadow"), "shadow");
        assert_eq!(s("C:\\Users\\me\\x.txt"), "x.txt");
        assert_eq!(s("a/b\\c/..\\d.txt"), "d.txt");
        assert_eq!(s("dir/"), "dir");
        assert_eq!(s(".."), "file");
        assert_eq!(s("../.."), "file");
        assert_eq!(s("/"), "file");
        assert_eq!(s(""), "file");
        assert_eq!(s("   "), "file");
    }

    #[test]
    fn hidden_and_odd_names_are_tamed() {
        assert_eq!(s(".bashrc"), "bashrc");
        assert_eq!(s("...hidden"), "hidden");
        assert_eq!(s("name."), "name");
        assert_eq!(s("name. . ."), "name");
        assert_eq!(s("a\0b\nc\td"), "abcd");
        assert_eq!(s("what?<really>*.txt"), "whatreally.txt");
        assert_eq!(s("C:evil.txt"), "Cevil.txt");
        // Right-to-left override: "photo\u{202e}gpj.exe" shows as "photoexe.jpg".
        assert_eq!(s("photo\u{202e}gpj.exe"), "photogpj.exe");
        assert_eq!(s("a\u{200b}b\u{feff}c"), "abc");
    }

    #[test]
    fn device_names_are_prefixed() {
        assert_eq!(s("CON"), "_CON");
        assert_eq!(s("nul.txt"), "_nul.txt");
        assert_eq!(s("com1"), "_com1");
        assert_eq!(s("LPT9.log"), "_LPT9.log");
        assert_eq!(s("COM0"), "COM0");
        assert_eq!(s("console.txt"), "console.txt");
    }

    #[test]
    fn long_names_are_shortened_on_character_boundaries() {
        let long = format!("{}.jpeg", "é".repeat(300));
        let out = s(&long);
        assert!(out.len() <= 200);
        assert!(out.ends_with(".jpeg"));
        let no_ext = "я".repeat(300);
        assert!(s(&no_ext).len() <= 200);
        let odd_ext = format!("x.{}", "e".repeat(400));
        assert!(s(&odd_ext).len() <= 200);
    }
}
