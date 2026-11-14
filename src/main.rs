use clap::Parser;

fn main() {
    let cli = rex_projects::cli::Cli::parse();
    if let Err(err) = rex_projects::cli::run(cli) {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}
