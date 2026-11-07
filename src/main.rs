fn main() {
    let code = match rex_projects::cli::run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            error.exit_code()
        }
    };
    std::process::exit(code);
}
