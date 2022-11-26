mod error;
mod mac;
mod chacha;
mod util;
mod otp;
mod types;
mod cli;
mod print;
mod ops;

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
    }
}