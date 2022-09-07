use libc;
use std::{
    self, io, mem,
    ops::{Deref, DerefMut},
};

const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

// T must be fixed size
pub struct SHM<T: Sized> {
    id: i32,
    size: usize,
    ptr: *mut T,
    owned: bool,
}

impl<T> SHM<T> {
    pub fn new() -> Self {
        let (id, size) = match Self::allocate_with_normal_pages() {
            Ok(map_info) => map_info,
            Err(error) => panic!("Could not allocate shared memory: {}", error),
        };

        let ptr = unsafe { libc::shmat(id, std::ptr::null(), 0) };
        if ptr == libc::MAP_FAILED {
            let error = io::Error::last_os_error();
            panic!("shmat(...): {}", error);
        }
        let ptr = ptr.cast();

        SHM::<T> {
            id,
            size,
            ptr,
            owned: true,
        }
    }

    pub fn new_huge() -> Self {
        let (id, size) = match Self::allocate_with_huge_pages() {
            Ok(map_info) => map_info,
            Err(error) => {
                log::warn!(
                    "Using normal shared pages, shared huge pages could not be allocated: {}",
                    error
                );

                match Self::allocate_with_normal_pages() {
                    Ok(map_info) => map_info,
                    Err(error) => panic!("Could not allocate shared memory: {}", error),
                }
            },
        };

        let ptr = unsafe { libc::shmat(id, std::ptr::null(), 0) };
        if ptr == libc::MAP_FAILED {
            let error = io::Error::last_os_error();
            panic!("shmat(...): {}", error);
        }
        let ptr = ptr.cast();

        SHM::<T> {
            id,
            size,
            ptr,
            owned: true,
        }
    }

    fn allocate_with_huge_pages() -> io::Result<(i32, usize)> {
        let size = (mem::size_of::<T>() / HUGE_PAGE_SIZE + 1) * HUGE_PAGE_SIZE;

        let id = unsafe {
            libc::shmget(
                libc::IPC_PRIVATE,
                size,
                libc::IPC_CREAT | libc::IPC_EXCL | libc::SHM_HUGETLB | 0o600,
            )
        };
        if id == -1 {
            return Err(io::Error::last_os_error());
        }

        Ok((id, size))
    }

    fn allocate_with_normal_pages() -> io::Result<(i32, usize)> {
        let size = mem::size_of::<T>();

        let id = unsafe {
            libc::shmget(
                libc::IPC_PRIVATE,
                size,
                libc::IPC_CREAT | libc::IPC_EXCL | 0o600,
            )
        };
        if id == -1 {
            return Err(io::Error::last_os_error());
        }

        Ok((id, size))
    }

    pub fn from_id(id: i32) -> Self {
        let size = std::mem::size_of::<T>() as usize;
        let ptr = unsafe { libc::shmat(id as libc::c_int, std::ptr::null(), 0) as *mut T };
        SHM::<T> {
            id,
            size,
            ptr,
            owned: false,
        }
    }

    pub fn clear(&mut self) {
        unsafe { libc::memset(self.ptr as *mut libc::c_void, 0, self.size) };
    }

    pub fn get_id(&self) -> i32 {
        self.id
    }

    pub fn get_ptr(&self) -> *mut T {
        self.ptr
    }

    pub fn is_fail(&self) -> bool {
        -1 == self.ptr as isize
    }
}

impl<T> Deref for SHM<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.ptr }
    }
}

impl<T> DerefMut for SHM<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.ptr }
    }
}

impl<T> std::fmt::Debug for SHM<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}, {}, {:p}", self.id, self.size, self.ptr)
    }
}

impl<T> Drop for SHM<T> {
    fn drop(&mut self) {
        if !self.owned {
            return;
        }

        let res = unsafe { libc::shmctl(self.id, libc::IPC_RMID, std::ptr::null_mut()) };
        if res == -1 {
            let error = io::Error::last_os_error();
            panic!("shmctl(...): {}", error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u8() {
        let mut one = SHM::<u8>::new();
        *one = 1;
        assert_eq!(1, *one);
    }

    #[test]
    fn test_array() {
        let mut arr = SHM::<[u8; 10]>::new();
        arr.clear();
        let sl = &mut arr;
        assert_eq!(0, sl[4]);
        sl[4] = 33;
        assert_eq!(33, sl[4]);
    }

    #[test]
    fn test_shm_fail() {
        let arr = SHM::<[u8; 10]>::from_id(88888888);
        assert!(arr.is_fail());

        let arr = SHM::<[u8; 10]>::new();
        assert!(!arr.is_fail());
        let arr2 = SHM::<[u8; 10]>::from_id(arr.get_id());
        assert!(!arr2.is_fail());
    }
}
