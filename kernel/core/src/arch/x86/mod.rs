// SPDX-License-Identifier: MPL-2.0

pub(crate) mod cpu;
#[cfg(not(feature = "kernelet"))]
mod power;
pub(crate) mod ptrace;
pub(crate) mod signal;

pub(crate) fn init() {
    #[cfg(not(feature = "kernelet"))]
    power::init();
}
