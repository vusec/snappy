#[derive(Clone, Copy)]
pub enum FuzzType {
    ExploreFuzz,
    ExploitFuzz,
    CmpFnFuzz,
    LenFuzz,
    AFLFuzz,
    OtherFuzz,
}

pub const FUZZ_TYPE_NUM: usize = FuzzType::OtherFuzz as usize + 1;
static FUZZ_TYPE_NAME: [&str; FUZZ_TYPE_NUM] =
    ["Explore", "Exploit", "CmpFn", "Len", "AFL", "Other"];

impl Default for FuzzType {
    fn default() -> Self {
        FuzzType::OtherFuzz
    }
}

impl FuzzType {
    pub fn index(&self) -> usize {
        *self as usize
    }

    pub fn modifies_tainted_only(self) -> bool {
        match self {
            FuzzType::ExploreFuzz => true,
            FuzzType::ExploitFuzz => true,
            FuzzType::CmpFnFuzz => false,
            FuzzType::LenFuzz => false,
            FuzzType::AFLFuzz => false,
            FuzzType::OtherFuzz => false,
        }
    }
}

pub fn get_fuzz_type_name(i: usize) -> String {
    FUZZ_TYPE_NAME[i].to_string()
}
