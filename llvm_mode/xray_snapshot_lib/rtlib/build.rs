use std::{env, path::PathBuf, str::FromStr};

fn main() {
    println!("cargo:rerun-if-changed=wrapper.hpp");

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

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("xray_bindings.rs"))
        .expect("Could not write bindings");
}
