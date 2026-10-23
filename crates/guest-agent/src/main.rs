#[cfg(target_os = "linux")]
mod linux;

fn main() {
    #[cfg(target_os = "linux")]
    if let Err(error) = linux::run() {
        eprintln!("Guest init failed: {error:#}");
        linux::shutdown();
    }
    #[cfg(not(target_os = "linux"))]
    eprintln!("The guest agent is built for Linux; build guest assets in the Linux CI job.");
}
