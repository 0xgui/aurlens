use std::process::ExitCode;

fn main() -> ExitCode {
    aurlens::cli::run("aurlens", std::env::args_os().skip(1))
}
