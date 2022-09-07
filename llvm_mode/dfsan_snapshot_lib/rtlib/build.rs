use std::{env, path::PathBuf, str::FromStr};

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=wrapper.hpp");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    println!("Build DFSan bindings:");
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .whitelist_type("dfsan_label")
        .whitelist_function("dfsan_create_label")
        .whitelist_function("dfsan_set_label")
        .whitelist_function("dfsan_read_label")
        .size_t_is_usize(true)
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_path.join("bindings_dfsan.rs"))
        .expect("Could not write bindings");

    println!("Build XRay bindings:");
    let bindings = bindgen::Builder::default()
        .header("wrapper.hpp")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .whitelist_function("__xray_init")
        .whitelist_function("__xray_set_handler")
        .whitelist_function("__xray_patch_function")
        .whitelist_function("__xray_unpatch_function")
        .default_enum_style(bindgen::EnumVariation::from_str("rust").unwrap())
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_path.join("bindings_xray.rs"))
        .expect("Could not write bindings");

    println!("Build format_buffer library:");
    cc::Build::new()
        .cpp(true)
        .compiler("clang++")
        .file("format_buffer/format_buffer.cpp")
        .compile("format_buffer");
}
