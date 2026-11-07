fn main() {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() == Some(std::ffi::OsStr::new("--version")) && args.next().is_none() {
        println!("rex-projects {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    eprintln!("rex-projects runtime is not implemented yet");
    std::process::exit(1);
}
