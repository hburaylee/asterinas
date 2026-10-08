// SPDX-License-Identifier: MPL-2.0

fn main() {
    if std::env::args().any(|argument| matches!(argument.as_str(), "-v" | "-version" | "--version"))
    {
        println!("containerd-shim-kernelet-v2 {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    kernelet_userspace::shim::run();
}
