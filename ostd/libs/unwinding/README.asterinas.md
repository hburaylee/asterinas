# Asterinas unwinding adaptation

This directory contains the published `unwinding` 0.2.10 source. Its crates.io
archive checksum is
`4b134ada16dda9e435abe2a6d76a01d497bc60707357845a15f9b0ed42dc88ce`.
The original MIT and Apache-2.0 licenses are included. All upstream Rust source
is unchanged except `src/unwinder/arch/x86_64.rs`.

The `kernelet-no-fp-control` feature is enabled only by OSTD's `kernelet`
feature. Kernelet kernel code has no ordinary floating-point ABI state, and
the final image audit rejects ordinary FP/SIMD instructions. User FPU state
belongs to the user-thread hooks; Host carrier switches preserve the live
processor state. The unwinder therefore does not separately capture or restore
MXCSR and the x87 control word in this configuration. It initializes the two
unused context slots with integer stores and keeps the upstream context layout,
stack offsets, general-register operations, and CFI unchanged.

Native builds do not enable this feature and retain the upstream control-word
save and restore. Guest and Host images are separate Cargo builds, so their
dependency features are resolved separately. This feature is not suitable for
ordinary code whose calling convention requires FP control-state preservation.

The manifest retains the published dependency and feature definitions, adds
the Guest-only feature and workspace lints, and omits the upstream integration
test target: the published archive does not include its `test_crates` inputs.
Workspace profiles supply the build profile.
