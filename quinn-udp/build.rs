use cfg_aliases::cfg_aliases;

fn main() {
    // Setup cfg aliases
    cfg_aliases! {
        // Platforms
        apple: {
            any(
                target_os = "macos",
                target_os = "ios",
                target_os = "tvos",
                target_os = "visionos"
            )
        },
        bsd: {
            any(
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd"
            )
        },
        // Convenience aliases
        apple_fast: { all(apple, feature = "fast-apple-datapath") },
        apple_slow: { all(apple, not(feature = "fast-apple-datapath")) },
    }
}
