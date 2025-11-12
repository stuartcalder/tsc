/* *
 * tsc - Implement Threefish, Skein, and CATENA cryptographic algorithms.
 * Copyright (C) 2025 Stuart Calder
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#![allow(unused_imports)]
use crate::tf512::NUM_BLOCK_BYTES;
use rssc::mmap;
use rssc::c;
use rssc::op;

use std::mem::ManuallyDrop;
use std::alloc;

use alloc::Layout;
use mmap::Map;

#[repr(C)]
pub struct SecureMemAlternate
{
    pub ptr:  *mut u8,
    pub size: usize,
}

impl Default for SecureMemAlternate {
    fn default() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            size: 0usize
        }
    }
}

impl Drop for SecureMemAlternate {
    fn drop(&mut self) {
        // If we've allocated procedure with the drop.
        if ! self.ptr.is_null() {
            // Zero over the memory to destroy it.
            unsafe {op::SSC_secureZero(self.ptr as *mut _ as *mut op::c_void, self.size)};
            let layout = Layout::from_size_align(self.size, NUM_BLOCK_BYTES).unwrap();
            // Deallocate it.
            unsafe {alloc::dealloc(self.ptr, layout)};
            // Reset to defaults.
            *self = Self::default();
        }
    }
}

#[repr(C)]
pub union SecureMemUnion
{
    pub mem_map: ManuallyDrop<Map>,
    pub mem_alt: ManuallyDrop<SecureMemAlternate>,
}

pub const TAG_MAP:  u8 = 1u8;
pub const TAG_ALT:  u8 = 2u8;

#[repr(C)]
pub struct SecureMem
{
    mem_union: SecureMemUnion,
    tag:       u8,
}

impl SecureMem {
    pub fn new_in_place(place: &mut SecureMem, requested_size: usize) -> Result<(),()>
    {
        if requested_size == 0usize {
            return Err(());
        }
        // Does our MemMap implementation support secret maps?
        if mmap::HAS_INITSECRET {
            // It does. Try to create a secret map.
            let res = Map::new_secret(requested_size);
            if res.is_ok() {
                place.mem_union.mem_map = ManuallyDrop::new(res.unwrap());
                place.tag = TAG_MAP;
                return Ok(())
            }
        }
        // Reaching this point of the function means we need to try using SecureMemAlternate.
        let mut sma = SecureMemAlternate {
            ptr: std::ptr::null_mut(),
            size: requested_size,
        };
        let layout = Layout::from_size_align(requested_size, NUM_BLOCK_BYTES).unwrap();
        unsafe {sma.ptr = alloc::alloc(layout)};
        if sma.ptr.is_null() {
            return Err(());
        }
        place.mem_union.mem_alt = ManuallyDrop::new(sma);
        place.tag = TAG_ALT;
        Ok(())
    }
    pub fn new(requested_size: usize) -> Result<Self,()>
    {
        let mut sm = SecureMem {
            // Initialize this as a memory map so Rust stops complaining about it being
            // uninitialized. This doesn't matter since interactions are controlled by the
            // tag, which is initialized to 0u8.
            mem_union: SecureMemUnion {
                mem_map: ManuallyDrop::new(Map::default())
            },
            tag: 0u8,
        };
        Self::new_in_place(&mut sm, requested_size)?;
        Ok(sm)
    }
    pub fn is_initialized(&self) -> bool
    {
        self.tag == TAG_MAP || self.tag == TAG_ALT
    }
    pub fn get_raw_ptr(&mut self) -> Result<*mut u8, ()>
    {
        match self.tag {
            TAG_MAP => {
                let map = unsafe {
                    &mut *self.mem_union.mem_map
                };
                Ok(map.get_ptr())
            },
            TAG_ALT => {
                let alt = unsafe {
                    &mut *self.mem_union.mem_alt
                };
                Ok(alt.ptr)
            },
            _ => Err(())
        }
    }
    pub fn get_mem(&mut self) -> Result<&mut [u8], ()>
    {
        match self.tag {
            TAG_MAP => {
                let map = unsafe {
                    &mut *self.mem_union.mem_map
                };
                let m  = unsafe {
                    std::slice::from_raw_parts_mut(
                        map.get_ptr(),
                        map.get_size()
                    )
                };
                Ok(m)
            },
            TAG_ALT => {
                let alt = unsafe {
                    &mut *self.mem_union.mem_alt
                };
                let m = unsafe {
                    std::slice::from_raw_parts_mut(
                        alt.ptr,
                        alt.size
                    )
                };
                Ok(m)
            },
            _ => {
                Err(())
            }
        }
    }
    pub fn get_size(&self) -> Result<usize, ()>
    {
        match self.tag {
            TAG_MAP => {
                let map = unsafe {
                    & *self.mem_union.mem_map
                };
                Ok(map.get_size())
            },
            TAG_ALT => {
                let alt = unsafe {
                    & *self.mem_union.mem_alt
                };
                Ok(alt.size)
            },
            _ => Err(())
        }
    }
    pub fn resize(&mut self, new_size: usize) -> Result<(), ()>
    {
        if new_size == self.get_size()? {
            return Ok(());
        }
        match self.tag {
            TAG_MAP => {
                let map = unsafe {
                    &mut *self.mem_union.mem_map
                };
                map.resize(new_size)?;
            },
            TAG_ALT => {
                // Get a mutable reference to the SecureMemAlternate.
                let alt = unsafe {
                    &mut *self.mem_union.mem_alt
                };
                let alt_size = alt.size;
                // Get the layout and try to allocate new memory.
                let layout_res = Layout::from_size_align(new_size, NUM_BLOCK_BYTES);
                if layout_res.is_err() {
                    return Err(());
                }
                let layout = layout_res.unwrap();
                let p: *mut u8 = unsafe {alloc::alloc(layout)};
                if p.is_null() {
                    return Err(());
                }
                // Form a slice that references the newly allocated memory.
                let p_slice = unsafe {std::slice::from_raw_parts_mut(p, new_size)};
                // Get a mutable reference to the SecureMemAlternate's allocated memory that we're
                // resizing.
                let alt_mem_res = self.get_mem();
                if alt_mem_res.is_err() {
                    return Err(());
                }
                let alt_mem = alt_mem_res.unwrap();
                // Is it growing in size?
                if new_size > alt_size {
                    // We need to ensure the new bytes are initially zero.
                    p_slice[alt_size..].fill(0u8);
                }
                // Copy the data into the newly allocated memory.
                p_slice[..alt_size].copy_from_slice(alt_mem);
                unsafe {
                    // Drop the original.
                    ManuallyDrop::drop(&mut self.mem_union.mem_alt);
                    // Create the replacement.
                    self.mem_union.mem_alt = ManuallyDrop::new(
                        SecureMemAlternate {
                            ptr: p, size: new_size
                        }
                    );
                }
            },
            _ => return Err(())
        }
        Ok(())
    }
    pub fn get_tag(&self) -> u8
    {
        self.tag
    }
}

impl Drop for SecureMem {
    fn drop(&mut self) {
        match self.tag {
            TAG_MAP => {
                unsafe {
                    ManuallyDrop::drop(&mut self.mem_union.mem_map);
                }
            },
            TAG_ALT => {
                unsafe {
                    ManuallyDrop::drop(&mut self.mem_union.mem_alt);
                }
            },
            _ => {}
        }
    }
}
