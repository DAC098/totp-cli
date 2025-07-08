mod chacha;
mod cli;
mod error;
mod mac;
mod ops;
mod otp;
mod print;
mod types;
mod util;

fn main() {
    let mut args = std::env::args();
    args.next();

    if let Err(err) = ops::run(args) {
        if let Some(msg) = err.message {
            print!("{}: {}", err.kind, msg);
        } else {
            print!("{}", err.kind);
        }

        if let Some(src) = err.source {
            print!("\n{}", src);
        }

        print!("\n");

        ops::help::print_ops();
    }
}
