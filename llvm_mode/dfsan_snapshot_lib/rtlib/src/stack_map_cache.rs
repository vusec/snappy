use findshlibs::{Avma, SharedLibrary, Svma, TargetSharedLibrary};
use memmap::Mmap;
use object::{Object, ObjectSection};
use snafu::{OptionExt, ResultExt, Snafu};
use stackmap::LLVMStackMaps;
use std::{
    collections::{
        btree_map::{Entry, VacantEntry},
        BTreeMap,
    },
    fs, io,
    path::{Path, PathBuf},
    result, slice,
};

const STACK_MAPS_SECTION_NAME: &str = ".llvm_stackmaps";

#[derive(Default)]
pub struct StackMapCache {
    // The section containing the stackmaps can be considered 'static, as long
    // as `dlclose` is not taken into account. However, it is not possible to
    // track that with lifetimes anyway.
    cache: BTreeMap<PathBuf, LLVMStackMaps<'static>>,
}

impl StackMapCache {
    fn add_missing_stackmap<'map>(
        vacant_entry: VacantEntry<'map, PathBuf, LLVMStackMaps<'static>>,
    ) -> Result<&'map LLVMStackMaps<'static>> {
        let path = vacant_entry.key();

        log::debug!("Searching stack maps section for: {}", path.display());

        let binary_file = fs::File::open(&path).context(BinaryFileNotFound {
            path: path.to_path_buf(),
        })?;
        let file_map = unsafe {
            Mmap::map(&binary_file).context(MmapFailed {
                path: path.to_path_buf(),
            })?
        };
        let object = object::File::parse(&file_map).context(ParseFailed {
            path: path.to_path_buf(),
        })?;

        let stackmaps_section =
            object
                .section_by_name(STACK_MAPS_SECTION_NAME)
                .context(StackMapsSectionNotFound {
                    path: path.to_path_buf(),
                })?;

        let stackmaps_section_svma = Svma(stackmaps_section.address() as usize);
        log::debug!("Section SVMA: {}", stackmaps_section_svma);

        let mut stackmaps_section_avma = None;
        TargetSharedLibrary::each(|shlib| {
            if shlib.name() == path.as_os_str() {
                let stackmaps_section_svma: usize = stackmaps_section_svma.into();
                let shared_library_bias: usize = shlib.virtual_memory_bias().into();
                stackmaps_section_avma = Some(Avma(stackmaps_section_svma + shared_library_bias));
            }
        });
        let stackmap_section_avma = stackmaps_section_avma.context(ObjectNotLoaded {
            path: path.to_path_buf(),
        })?;
        log::debug!("Section AVMA: {}", stackmap_section_avma);

        let stackmaps_section_ptr = usize::from(stackmap_section_avma) as *const u8;
        let stackmaps_slice = unsafe {
            slice::from_raw_parts(stackmaps_section_ptr, stackmaps_section.size() as usize)
        };

        let llvm_stack_maps = LLVMStackMaps::new(stackmaps_slice);

        Ok(vacant_entry.insert(llvm_stack_maps))
    }

    pub fn get_stack_map(&mut self, path: impl AsRef<Path>) -> Result<&LLVMStackMaps> {
        match self.cache.entry(path.as_ref().to_path_buf()) {
            Entry::Occupied(occupied) => Ok(occupied.into_mut()),
            Entry::Vacant(vacant) => Self::add_missing_stackmap(vacant),
        }
    }
}

type Result<T> = result::Result<T, Error>;
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Could not find binary file '{}': {}", path.display(), source))]
    BinaryFileNotFound { path: PathBuf, source: io::Error },
    #[snafu(display("Could not map binary file '{}' in memory: {}", path.display(), source))]
    MmapFailed { path: PathBuf, source: io::Error },
    #[snafu(display("Could not parse binary file '{}' as object: {}", path.display(), source))]
    ParseFailed {
        path: PathBuf,
        source: object::Error,
    },
    #[snafu(display("{} section not found in object: {}", STACK_MAPS_SECTION_NAME, path.display()))]
    StackMapsSectionNotFound { path: PathBuf },
    #[snafu(display("Could not find object '{}' among loaded ones", path.display()))]
    ObjectNotLoaded { path: PathBuf },
}
