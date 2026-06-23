use which::which;

/// Building this crate has an undeclared dependency on the `bpf-linker` binary.
/// Cause cargo to rebuild whenever the mtime of `which bpf-linker` changes.
fn main() {
    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}
