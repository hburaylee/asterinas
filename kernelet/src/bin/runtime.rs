// SPDX-License-Identifier: MPL-2.0

use clap::Parser;

fn main() {
    match kernelet_userspace::runtime::run(kernelet_userspace::runtime::Cli::parse()) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("kernelet-runtime: {error:#}");
            std::process::exit(1);
        }
    }
}
