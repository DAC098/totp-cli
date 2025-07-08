use clap::Parser;

mod chacha;
mod cli;
mod error;
mod mac;
mod ops;
mod otp;
mod path;
mod print;
mod types;
mod util;

#[derive(Debug, Parser)]
struct CliArgs {
    #[command(subcommand)]
    op: ops::OpCmd,
}

fn main() {
    let args = CliArgs::parse();

    if let Err(err) = ops::run(args.op) {
        if let Some(msg) = err.message {
            println!("{}: {}", err.kind, msg);
        } else {
            println!("{}", err.kind);
        }

        if let Some(src) = err.source {
            println!("{}", src);
        }
    }
}
