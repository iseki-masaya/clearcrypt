// Copyright (c) 2014, Cedric Staub <cs.staub@cssx.cc>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#![feature(asm)]
#![feature(macro_rules)]

extern crate test;

use std::cast;
use std::os;

use std::cmp::min;
use std::libc::types::common::c95::c_void;
use std::libc::funcs::posix88::mman::mlock;

use test::BenchHarness;

//--------
// Macros
//--------

// Bitwise left-rotate
macro_rules! rotl32(
  ($val:expr, $n:expr) => (
    asm!("roll $2, $0" : "=r"($val) : "0"($val), "I"($n));
  );
)

// Qu$arter round
macro_rules! chacha_qround(
  ($block:expr, $a:expr, $b:expr, $c:expr, $d:expr) => ({
    $block[$a] += $block[$b];
    $block[$d] ^= $block[$a];
    rotl32!($block[$d], 16);
    $block[$c] += $block[$d];
    $block[$b] ^= $block[$c];
    rotl32!($block[$b], 12);
    $block[$a] += $block[$b];
    $block[$d] ^= $block[$a];
    rotl32!($block[$d], 8);
    $block[$c] += $block[$d];
    $block[$b] ^= $block[$c];
    rotl32!($block[$b], 7);
  });
)

//---------------------
// Main implementation
//---------------------

pub struct ChaCha {
  index: uint,
  state: [u32, ..16],
  block: [u32, ..16]
}

pub enum ChaChaError {
  InvalidKeyLength
}

// Update state
#[inline]
fn chacha_update_state(ctx: &mut ChaCha) {
  ctx.state[12] += 1;
  if ctx.state[12] == 0 {
    ctx.state[13] += 1;
  }
}

// Produce an output block
#[inline]
fn chacha_produce_block(ctx: &mut ChaCha) {
  for i in range(0, 16) {
    ctx.block[i] = ctx.state[i];
  }

  // Ten double rounds are twenty rounds
  for _ in range(0, 10) {
    unsafe {
      chacha_qround!(ctx.block, 0, 4, 8, 12);
      chacha_qround!(ctx.block, 1, 5, 9, 13);
      chacha_qround!(ctx.block, 2, 6, 10, 14);
      chacha_qround!(ctx.block, 3, 7, 11, 15);
      chacha_qround!(ctx.block, 0, 5, 10, 15);
      chacha_qround!(ctx.block, 1, 6, 11, 12);
      chacha_qround!(ctx.block, 2, 7, 8, 13);
      chacha_qround!(ctx.block, 3, 4, 9, 14);
    }
  }

  for i in range(0, 16) {
    ctx.block[i] += ctx.state[i];
  }
}

// Set up state
#[inline]
fn chacha_setup(
    ctx: &mut ChaCha,
    key: &[u8], nonce: &[u8, ..8], constant: &[u8, ..16]) {

  let c: &[u32, ..4] = unsafe { cast::transmute(constant) };
  for n in range(0, 4) {
    ctx.state[n] = c[n];
  }

  let offset = (key.len() / 4 - 4) as int;
  let k: &[u32] = unsafe { cast::transmute(key) };
  for n in range(0, 4) {
    ctx.state[n + 4] = k[n];
    ctx.state[n + 8] = k[n + offset];
  }

  let i: &[u32, ..2] = unsafe { cast::transmute(nonce) };
  for n in range(0, 2) {
    ctx.state[n + 14] = i[n];
  }

  ctx.state[12] = 0;
  ctx.state[13] = 0;
}

// Method functions
impl ChaCha {
  // Initialize context
  pub fn new(key: &[u8], nonce: &[u8, ..8]) -> Result<ChaCha, ChaChaError> {
    if key.len() != 16 && key.len() != 32 {
      return Err(InvalidKeyLength);
    }

    let constant =
        if key.len() == 16 {
            [0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x31,
             0x36, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b]
        } else {
            [0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33,
             0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b]
        };

    let mut ctx = ChaCha {
      index: 0,
      state: [0, ..16],
      block: [0, ..16]
    };

    unsafe {
      if mlock(ctx.state.as_ptr() as *c_void, 64) != 0 {
        fail!("Error on mlock(): {}", os::last_os_error());
      }

      if mlock(ctx.block.as_ptr() as *c_void, 64) != 0 {
        fail!("Error on mlock(): {}", os::last_os_error());
      }
    }

    chacha_setup(&mut ctx, key, nonce, &constant);
    chacha_produce_block(&mut ctx);

    return Ok(ctx);
  }

  // Update with input
  pub fn process(&mut self, input: &[u8]) -> ~[u8] {
    let stream: &[u8, ..64] = unsafe { cast::transmute(&self.block) };

    let mut offset = 0;
    let mut output = input.to_owned();

    let bytes = input.len();
    let count = min(bytes, 64 - self.index);

    for i in range(0, count) {
      output[i] = input[i] ^ stream[self.index + i];
    }

    self.index += count;
    self.index &= 0x3F;

    if self.index == 0 {
      chacha_update_state(self);
      chacha_produce_block(self);
    }

    if count == bytes {
      return output;
    }

    offset += count;

    while bytes - offset > 64 {
      for i in range(0, 64) {
        output[offset] = input[offset] ^ stream[i];
        offset += 1;
      }

      chacha_update_state(self);
      chacha_produce_block(self);
    }

    let remaining = bytes - offset;

    for i in range(0, remaining) {
      output[offset] = input[offset] ^ stream[i];
      offset += 1;
    }

    self.index = 64 - remaining;
    return output;
  }
}

impl Drop for ChaCha {
  fn drop(&mut self) {
    for i in range(0, 16) {
      self.state[i] = 0;
      self.block[i] = 0;
    }
  }
}

//-------
// Tests
//-------

#[test]
fn chacha20_test_vectors() {
  // Test vectors taken from:
  // https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7

  let key0 = [0, ..32];

  let nonce0 = [0, ..8];

  let expected0 = [
    0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
    0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
    0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
    0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
    0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
    0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
    0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
    0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86];

  let key1 = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

  let nonce1 = [0, ..8];

  let expected1 = [
    0x45, 0x40, 0xf0, 0x5a, 0x9f, 0x1f, 0xb2, 0x96,
    0xd7, 0x73, 0x6e, 0x7b, 0x20, 0x8e, 0x3c, 0x96,
    0xeb, 0x4f, 0xe1, 0x83, 0x46, 0x88, 0xd2, 0x60,
    0x4f, 0x45, 0x09, 0x52, 0xed, 0x43, 0x2d, 0x41,
    0xbb, 0xe2, 0xa0, 0xb6, 0xea, 0x75, 0x66, 0xd2,
    0xa5, 0xd1, 0xe7, 0xe2, 0x0d, 0x42, 0xaf, 0x2c,
    0x53, 0xd7, 0x92, 0xb1, 0xc4, 0x3f, 0xea, 0x81,
    0x7e, 0x9a, 0xd2, 0x75, 0xae, 0x54, 0x69, 0x63];

  let key2 = [0, ..32];

  let nonce2 = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

  let expected2 = [
    0xde, 0x9c, 0xba, 0x7b, 0xf3, 0xd6, 0x9e, 0xf5,
    0xe7, 0x86, 0xdc, 0x63, 0x97, 0x3f, 0x65, 0x3a,
    0x0b, 0x49, 0xe0, 0x15, 0xad, 0xbf, 0xf7, 0x13,
    0x4f, 0xcb, 0x7d, 0xf1, 0x37, 0x82, 0x10, 0x31,
    0xe8, 0x5a, 0x05, 0x02, 0x78, 0xa7, 0x08, 0x45,
    0x27, 0x21, 0x4f, 0x73, 0xef, 0xc7, 0xfa, 0x5b,
    0x52, 0x77, 0x06, 0x2e, 0xb7, 0xa0, 0x43, 0x3e,
    0x44, 0x5f, 0x41, 0xe3];

  let key3 = [0, ..32];

  let nonce3 = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

  let expected3 = [
    0xef, 0x3f, 0xdf, 0xd6, 0xc6, 0x15, 0x78, 0xfb,
    0xf5, 0xcf, 0x35, 0xbd, 0x3d, 0xd3, 0x3b, 0x80,
    0x09, 0x63, 0x16, 0x34, 0xd2, 0x1e, 0x42, 0xac,
    0x33, 0x96, 0x0b, 0xd1, 0x38, 0xe5, 0x0d, 0x32,
    0x11, 0x1e, 0x4c, 0xaf, 0x23, 0x7e, 0xe5, 0x3c,
    0xa8, 0xad, 0x64, 0x26, 0x19, 0x4a, 0x88, 0x54,
    0x5d, 0xdc, 0x49, 0x7a, 0x0b, 0x46, 0x6e, 0x7d,
    0x6b, 0xbd, 0xb0, 0x04, 0x1b, 0x2f, 0x58, 0x6b];

  let key4 = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];

  let nonce4 = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

  let expected4 = [
    0xf7, 0x98, 0xa1, 0x89, 0xf1, 0x95, 0xe6, 0x69,
    0x82, 0x10, 0x5f, 0xfb, 0x64, 0x0b, 0xb7, 0x75,
    0x7f, 0x57, 0x9d, 0xa3, 0x16, 0x02, 0xfc, 0x93,
    0xec, 0x01, 0xac, 0x56, 0xf8, 0x5a, 0xc3, 0xc1,
    0x34, 0xa4, 0x54, 0x7b, 0x73, 0x3b, 0x46, 0x41,
    0x30, 0x42, 0xc9, 0x44, 0x00, 0x49, 0x17, 0x69,
    0x05, 0xd3, 0xbe, 0x59, 0xea, 0x1c, 0x53, 0xf1,
    0x59, 0x16, 0x15, 0x5c, 0x2b, 0xe8, 0x24, 0x1a,
    0x38, 0x00, 0x8b, 0x9a, 0x26, 0xbc, 0x35, 0x94,
    0x1e, 0x24, 0x44, 0x17, 0x7c, 0x8a, 0xde, 0x66,
    0x89, 0xde, 0x95, 0x26, 0x49, 0x86, 0xd9, 0x58,
    0x89, 0xfb, 0x60, 0xe8, 0x46, 0x29, 0xc9, 0xbd,
    0x9a, 0x5a, 0xcb, 0x1c, 0xc1, 0x18, 0xbe, 0x56,
    0x3e, 0xb9, 0xb3, 0xa4, 0xa4, 0x72, 0xf8, 0x2e,
    0x09, 0xa7, 0xe7, 0x78, 0x49, 0x2b, 0x56, 0x2e,
    0xf7, 0x13, 0x0e, 0x88, 0xdf, 0xe0, 0x31, 0xc7,
    0x9d, 0xb9, 0xd4, 0xf7, 0xc7, 0xa8, 0x99, 0x15,
    0x1b, 0x9a, 0x47, 0x50, 0x32, 0xb6, 0x3f, 0xc3,
    0x85, 0x24, 0x5f, 0xe0, 0x54, 0xe3, 0xdd, 0x5a,
    0x97, 0xa5, 0xf5, 0x76, 0xfe, 0x06, 0x40, 0x25,
    0xd3, 0xce, 0x04, 0x2c, 0x56, 0x6a, 0xb2, 0xc5,
    0x07, 0xb1, 0x38, 0xdb, 0x85, 0x3e, 0x3d, 0x69,
    0x59, 0x66, 0x09, 0x96, 0x54, 0x6c, 0xc9, 0xc4,
    0xa6, 0xea, 0xfd, 0xc7, 0x77, 0xc0, 0x40, 0xd7,
    0x0e, 0xaf, 0x46, 0xf7, 0x6d, 0xad, 0x39, 0x79,
    0xe5, 0xc5, 0x36, 0x0c, 0x33, 0x17, 0x16, 0x6a,
    0x1c, 0x89, 0x4c, 0x94, 0xa3, 0x71, 0x87, 0x6a,
    0x94, 0xdf, 0x76, 0x28, 0xfe, 0x4e, 0xaa, 0xf2,
    0xcc, 0xb2, 0x7d, 0x5a, 0xaa, 0xe0, 0xad, 0x7a,
    0xd0, 0xf9, 0xd4, 0xb6, 0xad, 0x3b, 0x54, 0x09,
    0x87, 0x46, 0xd4, 0x52, 0x4d, 0x38, 0x40, 0x7a,
    0x6d, 0xeb, 0x3a, 0xb7, 0x8f, 0xab, 0x78, 0xc9];

  let mut ctx: ChaCha;
  ctx = ChaCha::new(key0, &nonce0).unwrap();
  let output0 = ctx.process([0, ..64]);

  ctx = ChaCha::new(key1, &nonce1).unwrap();
  let output1 = ctx.process([0, ..64]);

  ctx = ChaCha::new(key2, &nonce2).unwrap();
  let output2 = ctx.process([0, ..60]);

  ctx = ChaCha::new(key3, &nonce3).unwrap();
  let output3 = ctx.process([0, ..64]);

  ctx = ChaCha::new(key4, &nonce4).unwrap();
  let output4 = ctx.process([0, ..256]);

  assert_eq!(output0.slice(0, 64), expected0.slice(0, 64));
  assert_eq!(output1.slice(0, 64), expected1.slice(0, 64));
  assert_eq!(output2.slice(0, 60), expected2.slice(0, 60));
  assert_eq!(output3.slice(0, 64), expected3.slice(0, 64));
  assert_eq!(output4.slice(0, 256), expected4.slice(0, 256));
}

#[test]
fn chacha20_basic_test() {
  let buffer = [0, ..256];
  let mut ctx = ChaCha::new([0, ..32], &[0, ..8]).unwrap();
  for i in range(0, 256) {
    let output = ctx.process(buffer.slice(0, i as uint));
    assert_eq!(output.len(), i as uint);
  }
}

//------------
// Benchmarks
//------------

#[bench]
fn chacha20_process_16_kibs(bench: &mut test::BenchHarness) {
  bench.iter(|| {
    let mut ctx = ChaCha::new([0, ..32], &[0, ..8]).unwrap();
    ctx.process([0, ..16*1024]);
  });
}

#[bench]
fn chacha20_process_64_kibs(bench: &mut test::BenchHarness) {
  bench.iter(|| {
    let mut ctx = ChaCha::new([0, ..32], &[0, ..8]).unwrap();
    ctx.process([0, ..64*1024]);
  });
}