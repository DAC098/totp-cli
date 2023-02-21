use std::env::Args;

use crate::error;

pub mod help;
mod codes;
mod new;
mod add;
mod add_json;
mod add_url;
mod add_gauth;
mod view;
mod edit;
mod rename;
mod drop;

/// processes the first argument and then runs the desired operation
pub fn run(mut args: Args) -> error::Result<()> {
    let Some(op) = args.next() else {
        return Err(error::Error::new(error::ErrorKind::InvalidOp)
            .with_message("no operation specified"));
    };

    match op.as_str() {
        "help" => help::run(args),
        "codes" => codes::run(args),
        "new" => new::run(args),
        "add" => add::run(args),
        "add-json" => add_json::run(args), 
        "add-url" => add_url::run(args),
        "add-gauth" => add_gauth::run(args),
        "view" => view::run(args),
        "edit" => edit::run(args),
        "rename" => rename::run(args),
        "drop" => drop::run(args),
        _ => {
            let mut msg = String::from("given an unknown operation. \"");
            msg.push_str(&op);
            msg.push('"');

            Err(error::Error::new(error::ErrorKind::InvalidOp)
                .with_message(msg))
        }
    }
}
