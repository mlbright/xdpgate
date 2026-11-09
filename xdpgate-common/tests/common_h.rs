//! While C tools still build against common.h, it must describe the same maps
//! as this crate, byte for byte: both sides read and write the same pins.
//! Compiles a small C program against the headers and compares what it
//! prints with the same facts computed from xdpgate-common.

use std::mem::offset_of;
use std::path::Path;
use std::process::Command;

use xdpgate_common::*;

const PROBE_C: &str = r#"
#include <stddef.h>
#include <stdio.h>
#include "common.h"
#include "protected_conf.h"

int main(void)
{
	printf("pin dir %s\n", XDPGATE_PIN_DIR);
	printf("spa port %d\n", SPA_PORT);
	printf("allow icmp to protected %d\n", ALLOW_ICMP_TO_PROTECTED);
	printf("tcp %d udp %d\n", IPPROTO_TCP, IPPROTO_UDP);
	printf("protected max entries %d\n", PROT_MAX_ENTRIES);
	printf("prot_v6_key size %zu addr@%zu\n", sizeof(struct prot_v6_key),
	       offsetof(struct prot_v6_key, addr));
	printf("allow_v4_key size %zu saddr@%zu dport@%zu proto@%zu\n",
	       sizeof(struct allow_v4_key), offsetof(struct allow_v4_key, saddr),
	       offsetof(struct allow_v4_key, dport), offsetof(struct allow_v4_key, proto));
	printf("allow_v6_key size %zu saddr@%zu dport@%zu proto@%zu\n",
	       sizeof(struct allow_v6_key), offsetof(struct allow_v6_key, saddr),
	       offsetof(struct allow_v6_key, dport), offsetof(struct allow_v6_key, proto));
	printf("allow_val size %zu expiry_ns@%zu\n", sizeof(struct allow_val),
	       offsetof(struct allow_val, expiry_ns));
	return 0;
}
"#;

fn rust_facts() -> String {
    [
        format!("pin dir {}", PIN_DIR.to_str().unwrap()),
        format!("spa port {SPA_PORT}"),
        format!(
            "allow icmp to protected {}",
            u8::from(ALLOW_ICMP_TO_PROTECTED)
        ),
        format!("tcp {IPPROTO_TCP} udp {IPPROTO_UDP}"),
        format!("protected max entries {PROTECTED_MAX_ENTRIES}"),
        format!(
            "prot_v6_key size {} addr@{}",
            size_of::<ProtectedKey6>(),
            offset_of!(ProtectedKey6, addr)
        ),
        format!(
            "allow_v4_key size {} saddr@{} dport@{} proto@{}",
            size_of::<GrantKey4>(),
            offset_of!(GrantKey4, saddr),
            offset_of!(GrantKey4, dport),
            offset_of!(GrantKey4, proto)
        ),
        format!(
            "allow_v6_key size {} saddr@{} dport@{} proto@{}",
            size_of::<GrantKey6>(),
            offset_of!(GrantKey6, saddr),
            offset_of!(GrantKey6, dport),
            offset_of!(GrantKey6, proto)
        ),
        format!(
            "allow_val size {} expiry_ns@{}",
            size_of::<GrantExpiry>(),
            offset_of!(GrantExpiry, expiry_ns)
        ),
    ]
    .iter()
    .map(|line| format!("{line}\n"))
    .collect()
}

#[test]
fn common_h_matches_xdpgate_common() {
    let top = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let tmp = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let src = tmp.join("common_h_probe.c");
    let exe = tmp.join("common_h_probe");
    std::fs::write(&src, PROBE_C).unwrap();

    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let status = Command::new(&cc)
        .arg("-Wall")
        .arg("-I")
        .arg(&top)
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .status()
        .unwrap_or_else(|e| panic!("running {cc}: {e}"));
    assert!(
        status.success(),
        "{cc} could not compile the common.h probe"
    );

    let out = Command::new(&exe).output().unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), rust_facts());
}
