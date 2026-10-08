// SPDX-License-Identifier: MPL-2.0

fn main() {
    if let Err(error) = kernelet_userspace::agent::run() {
        eprintln!("kernelet-agent: {error:#}");
        std::process::exit(1);
    }
}
