// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

#![forbid(unsafe_code)]

use clap::Parser;
use net_specter::cli::Cli;
use net_specter::commands;
use net_specter::error::Result;

fn run() -> Result<()> {
    let cli = Cli::parse();
    commands::execute(cli.command)
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}
