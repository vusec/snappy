use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .whitelist_function("afl_snapshot_init")
        .whitelist_function("afl_snapshot_take")
        .whitelist_function("afl_snapshot_clean")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("afl_snapshot_bindings.rs"))
        .expect("Could not write bindings");

    cc::Build::new()
        .file("externals/AFL-Snapshot-LKM/lib/libaflsnapshot.c")
        .include("externals/AFL-Snapshot-LKM/include")
        .compile("aflsnapshot")
}
