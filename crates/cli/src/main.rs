//! Keyboard-only local client. No command launches a guest directly.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod client;

fn main() {
    #[cfg(target_os = "linux")]
    std::process::exit(client::run());

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("{{\"v\":1,\"ok\":false,\"error\":{{\"code\":\"UNSUPPORTED_HOST\",\"message\":\"the authenticated native Unix client requires Linux\",\"retryable\":false}}}}");
        std::process::exit(78);
    }
}
