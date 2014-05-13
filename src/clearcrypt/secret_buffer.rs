extern crate libc;

use std::os;
use std::mem::transmute;
use std::raw::Slice;

use libc::types::common::c95::c_void;
use libc::funcs::posix88::mman::{mmap, mlock, munmap};
use libc::consts::os::posix88::{PROT_READ, PROT_WRITE};
use libc::consts::os::posix88::{MAP_ANON, MAP_PRIVATE, MAP_FAILED};

pub struct SecretBuffer {
  len:    uint,
  ptr:    *mut u8,
  burned: bool
}

impl SecretBuffer {
  pub fn new(len: uint) -> SecretBuffer {
    let ptr = unsafe {
      // TODO: guard pages
      let c_ptr = mmap(0 as *c_void, len as u64, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0) as *c_void;

      if c_ptr == MAP_FAILED {
        fail!("mmap() failed: {}", os::last_os_error());
      }

      if mlock(c_ptr, len as u64) != 0 {
        fail!("mlock() failed: {}", os::last_os_error());
      }

      c_ptr as *mut u8
    };

    SecretBuffer { len: len, ptr: ptr, burned: false }
  }

  // Permanently destroy the buffer
  pub fn burn(&mut self) {
    if self.burned { return }

    unsafe {
      std::intrinsics::volatile_set_memory(self.ptr, 0u8, self.len);
      self.burned = true;
      munmap(self.ptr as *c_void, self.len as u64);
    }
  }

  // Temporarily expose the mutable buffer
  pub fn mut_expose(&mut self, mutator: |&mut [u8]|) {
    if self.burned {
      fail!("already burned!");
    }

    // TODO: protect the buffer
    mutator(self.as_mut_slice());
  }

  fn as_mut_slice(&mut self) -> &mut [u8] {
    unsafe { transmute(Slice { data: self.ptr as *u8, len: self.len }) }
  }
}

impl Drop for SecretBuffer {
  // Automatically destroy the buffer if it hasn't been done manually
  fn drop(&mut self) {
    self.burn()
  }
}

#[test]
fn test_zero_initialization() {
  let mut secret = SecretBuffer::new(4);
  let expected = [0u8, ..4];

  secret.mut_expose(|actual| {
    assert!(expected == actual);
  });
}

#[test]
fn test_stores_data() {
  let mut secret = SecretBuffer::new(4);
  let expected: [u8, ..4] = [1, 2, 3, 4];

  secret.mut_expose(|buf| {
    buf[0] = 1;
    buf[1] = 2;
    buf[2] = 3;
    buf[3] = 4;
  });

  secret.mut_expose(|actual| {
    assert!(expected == actual);
  });
}

#[test]
fn test_repeat_burning() {
  let mut secret = SecretBuffer::new(4);

  secret.burn();
  secret.burn();
  secret.burn(); // Burn baby, burn!
}
