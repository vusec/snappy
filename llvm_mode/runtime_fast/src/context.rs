#[link(name = "context", kind = "static")]
extern "C" {
    pub fn __angora_get_context() -> u32;
    pub fn __angora_get_prev_loc() -> u32;
}

pub fn get_context() -> u32 {
    unsafe { __angora_get_context() }
}

pub fn get_prev_loc() -> u32 {
    unsafe { __angora_get_prev_loc() }
}
