use std::fmt;
use std::u64;
use libc::c_char;
use std::collections::BTreeMap;

use radare2::*;

use bb::BasicBlock;

pub struct Function {
    pub entry: u64,
    pub size: u64,
    pub blocks: BTreeMap<u64, BasicBlock>,
    pub score: i64,
}

impl fmt::Display for Function {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "s: 0x{:x}\t blocks: {}\t score:{}", self.entry, self.blocks.len() + 1, self.score)
    }
}

impl Function {
    pub fn new(addr: u64) -> Function {
        Function { entry: addr, size: 0, blocks: BTreeMap::new(), score: 0 }
    }

    pub fn add_block(&mut self, block: BasicBlock) {
        if block.end < u64::MAX {
            self.score += block.score;
            self.size += block.size();
            self.blocks.entry(block.start).or_insert(block);
        } else {
            //println!("Adding malformed block: {} to {}", block, self);
        }
    }

    pub fn block_count(&self) -> usize {
        return self.blocks.len()
    }

    pub fn contains_block(&self, addr: u64) -> bool {
        self.blocks.contains_key(&addr)
    }

    pub fn get_score(&self) -> i64 {
        self.score
    }

    pub fn dump_r2_commands(&self) {
        unsafe {
            let s : String = format!("af+ 0x{:x} fcn.{:x}\n", self.entry, self.entry);
            // r_cons_strcat(CString::new(s).unwrap().as_ptr());
            r_cons_strcat(s.as_ptr() as *const c_char);
            //XXX adding flags should be implicit through af+
            let s2 : String = format!("f fcn.{:x} {} @ {}\n", self.entry, self.size, self.entry);
            r_cons_strcat(s2.as_ptr() as *const c_char); // CString::new(s2).unwrap().as_ptr());
        }
        for (_, bb) in &self.blocks {
            let s: String;
            if bb.jump != u64::MAX {
                if bb.fail != u64::MAX {
                    s = format!("afb+ 0x{:x} 0x{:x} 0x{:x} 0x{:x} 0x{:x}\n",
                        self.entry, bb.start, bb.end - bb.start,
                        bb.jump, bb.fail);
                } else {
                    s = format!("afb+ 0x{:x} 0x{:x} 0x{:x} 0x{:x}\n",
                        self.entry, bb.start, bb.end - bb.start,
                        bb.jump);
                }
            } else {
                 s = format!("afb+ 0x{:x} 0x{:x} 0x{:x}\n", self.entry, bb.start, bb.end - bb.start);
	        }
            unsafe {
                r_cons_strcat(s.as_ptr() as *const c_char); // CString::new(s).unwrap().as_ptr());
            }
        }
    }
}

