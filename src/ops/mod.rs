use clap::Subcommand;

use crate::error;

mod add;
mod add_gauth;
mod add_json;
mod add_url;
mod codes;
mod drop;
mod edit;
mod new;
mod rename;
mod view;

#[derive(Debug, Subcommand)]
pub enum OpCmd {
    Codes(codes::CodesArgs),
    New(new::NewArgs),
    Add(add::AddArgs),
    AddJson(add_json::AddJsonArgs),
    AddUrl(add_url::AddUrlArgs),
    AddGauth(add_gauth::AddGauthArgs),
    View(view::ViewArgs),
    Edit(edit::EditArgs),
    Rename(rename::RenameArgs),
    Drop(drop::DropArgs),
}

/// processes the first argument and then runs the desired operation
pub fn run(cmd: OpCmd) -> error::Result<()> {
    match cmd {
        OpCmd::Codes(args) => codes::run(args),
        OpCmd::New(args) => new::run(args),
        OpCmd::Add(args) => add::run(args),
        OpCmd::AddJson(args) => add_json::run(args),
        OpCmd::AddUrl(args) => add_url::run(args),
        OpCmd::AddGauth(args) => add_gauth::run(args),
        OpCmd::View(args) => view::run(args),
        OpCmd::Edit(args) => edit::run(args),
        OpCmd::Rename(args) => rename::run(args),
        OpCmd::Drop(args) => drop::run(args),
    }
}
