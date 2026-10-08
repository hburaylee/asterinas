// SPDX-License-Identifier: MPL-2.0

//! Generates the C UAPI from the Rust layouts and evaluated ioctl constants.

use std::{fs::OpenOptions, io::Write};

use kernelet_abi as abi;

fn main() {
    let output = std::env::args_os().nth(1).expect("usage: header OUTPUT.h");
    macro_rules! layouts {
        ($($name:ident { $($field:ident),* $(,)? }),* $(,)?) => {
            vec![$((
                stringify!($name),
                size_of::<abi::$name>(),
                vec![$((stringify!($field), std::mem::offset_of!(abi::$name, $field))),*],
            )),*]
        };
    }
    let layouts = layouts!(
        CreateArgs {
            image,
            num_vcpus,
            initial_grains,
            max_grains,
            max_meta_sections,
            nice,
            reserved0,
            cpu_quota_us,
            cpu_period_us,
            oops_budget,
            log_bytes_per_sec,
            max_tasks,
            cmdline_ptr,
            cmdline_len,
            out_cid,
        },
        AttachArgs {
            kind,
            vcpu,
            backing_fd,
            flags,
            out_index,
            reserved0,
            arg
        },
        EndpointArgs { kind, reserved0 },
        NetPortMapping {
            host_address,
            host_port,
            guest_port,
            protocol,
            reserved0
        },
        NetConfigArgs {
            host_resolver,
            num_ports,
            reserved0,
            ports
        },
        VsockArgs { port, flags },
        VsockPolicyArgs { peer_fd, allow },
        BudgetArgs {
            nice,
            reserved0,
            cpu_quota_us,
            cpu_period_us
        },
        StatsRaw {
            state,
            cid,
            grains_granted,
            max_grains,
            stacks_allocated,
            oopses,
            host_bytes_charged,
            host_overhead_bytes,
            cpu_time_ns,
            throttled_ns,
            completion_cpu_ns,
            ingress_copy_cpu_ns,
            service_calls,
            mmio_accesses,
            irqs_raised,
            log_bytes,
            log_records_dropped,
        },
        StatusRaw {
            state,
            reason,
            code,
            flags,
            uptime_ns,
            cpu_time_ns,
            fault_addr,
            fault_ip,
            message_len,
            reserved0,
            message,
        },
        ImageInfoRaw {
            image,
            name_len,
            name,
            reserved0,
            text_bytes,
            template_bytes,
            cpu_local_bytes,
            reserved1,
        },
    );
    let mut config = cbindgen::Config {
        language: cbindgen::Language::C,
        include_guard: Some("ASTERINAS_KERNELET_ABI_H".into()),
        ..Default::default()
    };
    config.export.prefix = Some("KERNELET_".into());
    config.export.include = layouts.iter().map(|(name, _, _)| (*name).into()).collect();
    cbindgen::Builder::new()
        .with_crate(env!("CARGO_MANIFEST_DIR"))
        .with_config(config)
        .generate()
        .expect("generate ABI header")
        .write_to_file(&output);
    let mut file = OpenOptions::new().append(true).open(output).unwrap();
    writeln!(file, "#include <stddef.h>").unwrap();
    // Cbindgen cannot evaluate const function calls. Rust evaluates the ioctl
    // encodings here, keeping their values tied to the actual structure sizes.
    macro_rules! requests {
        ($($name:ident),* $(,)?) => {$({
            writeln!(file,"#ifndef KERNELET_{}\n#define KERNELET_{} UINT64_C({})\n#endif",stringify!($name),stringify!($name),abi::$name).unwrap();
        })*};
    }
    requests!(
        CREATE,
        LIST_IMAGES,
        ATTACH,
        ENDPOINT,
        NET_CONFIG,
        START,
        KILL,
        GRANT,
        BUDGET,
        STATS,
        STATUS,
        DESTROY,
        VSOCK_CONNECT,
        VSOCK_LISTEN,
        VSOCK_SHUTDOWN,
        VSOCK_POLICY
    );
    for (name, size, fields) in layouts {
        writeln!(
            file,
            r#"_Static_assert(sizeof(struct KERNELET_{name}) == {size}, "{name} layout mismatch");"#
        )
        .unwrap();
        for (field, offset) in fields {
            writeln!(
                file,
                r#"_Static_assert(offsetof(struct KERNELET_{name}, {field}) == {offset}, "{name}.{field} offset mismatch");"#
            )
            .unwrap();
        }
    }
}
