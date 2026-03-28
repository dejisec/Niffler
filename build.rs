fn main() {
    let target_family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    if target_family != "unix" {
        panic!("Niffler requires a Unix target (NFS is not available on Windows)");
    }

    println!("cargo:rerun-if-changed=build.rs");

    let lib = pkg_config::Config::new()
        .probe("libnfs")
        .expect("libnfs not found — install libnfs-dev or libnfs via your package manager");

    for path in &lib.link_paths {
        println!("cargo:rustc-link-search=native={}", path.display());
    }
    for l in &lib.libs {
        println!("cargo:rustc-link-lib={l}");
    }
    for fw_path in &lib.framework_paths {
        println!("cargo:rustc-link-search=framework={}", fw_path.display());
    }
    for fw in &lib.frameworks {
        println!("cargo:rustc-link-lib=framework={fw}");
    }
}
