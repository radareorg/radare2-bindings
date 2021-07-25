use libc::*;
use std::u64;
use std::io::Write;
use serde::Deserialize;
use std::collections::HashMap;

use bb::BlockType;
use bb::BasicBlock;

use fcn::Function;

use radare2::*;

pub struct Anal {
    pub blocks: Vec<BasicBlock>,
    pub block_map : HashMap<u64, BasicBlock>,
    pub calls: Vec<u64>,
    pub jumps: HashMap<u64, u64>,
    pub functions: Vec<Function>,
    pub core: *mut c_void,
    call_ref: HashMap<u64, u64>,
    data_ref: HashMap<u64, u64>,
}

macro_rules! stderr {
    ($($arg:tt)*) => (
        match writeln!(&mut ::std::io::stderr(), $($arg)* ) {
            Ok(_) => {},
            Err(x) => panic!("Unable to write to stderr (file handle closed?): {}", x),
        }
    )
}

#[derive(Deserialize)]
pub struct Section {
    flags: String,
    name: String,
    paddr: u64,
    size: u64,
    vaddr: u64,
    vsize: u64,
}

impl Anal {
    pub fn new(core: *mut c_void) -> Anal {
        Anal { 
            blocks: Vec::new(),
            block_map: HashMap::new(),
            call_ref: HashMap::new(),
            data_ref: HashMap::new(),
            calls: Vec::new(),
            jumps: HashMap::new(),
            functions: Vec::new(),
            core: core,
        }
    }

    pub fn add(&mut self, start: u64, end: u64, jump: u64, fail: u64, t: BlockType, score: i64) {
        let block = BasicBlock { start: start, end: end, jump: jump, fail: fail, block_type: t, score: score};
        if jump < u64::MAX {
            let jump_bb = BasicBlock { start: jump, end: u64::MAX, jump: u64::MAX, fail: u64::MAX, block_type: t, score: score};
            self.blocks.push(jump_bb);
        }
        self.blocks.push(block);
    }

    pub fn analyze(&mut self) {
        //r2_cmd(self.core, "e anal.afterjmp=false");
        //r2_cmd(self.core, "e anal.vars=false");
        let section_json= r2_cmd(self.core, "iSj");
        let sections: Vec<Section> = serde_json::from_str(section_json).unwrap();

        let offset_inside = |x: u64| -> bool {
            for section in &sections {
                if x >= section.vaddr && x <= section.vaddr + section.size {
                    return true;
                }
            }
            false
        };

        for section in sections.iter().filter(| x | x.flags.contains("x")) {
            let start: u64 = section.vaddr;
            let size: u64 = section.size;

            let mut cur: u64 = 0;
            let mut b_start: u64 = start;
            let mut block_score: i64 = 0;
            while cur < size {
                unsafe {
                    let op: *mut RAnalOp;
                    op = r_core_anal_op (self.core, start + cur);

                    if op.is_null() {
                        cur += 1;
                        block_score -= 10;
                        continue;
                    } else {
                        match (*op)._type {
                            R_ANAL_OP_TYPE_NOP => {
                            }
                            R_ANAL_OP_TYPE_CALL => {
                                self.add((*op).jump, u64::MAX, u64::MAX, u64::MAX, BlockType::Call, block_score);
                                if offset_inside((*op).jump) {
                                    self.call_ref.entry(start + cur).or_insert((*op).jump);
                                }
                                block_score = 0;
                            }
                            R_ANAL_OP_TYPE_RET => {
                                self.add(b_start, start + cur + (*op).size as u64, u64::MAX, u64::MAX, BlockType::Normal, block_score);
                                b_start = start + cur + (*op).size as u64;
                                block_score = 0;
                            }
                            R_ANAL_OP_TYPE_CJMP => {
                                self.add(b_start, start + cur + (*op).size as u64, (*op).jump, (*op).size as u64 + cur + start, BlockType::Normal, block_score);
                                b_start = start + cur + (*op).size as u64;
                                block_score = 0;
                            }

                            R_ANAL_OP_TYPE_JMP | R_ANAL_OP_TYPE_UJMP | R_ANAL_OP_TYPE_RJMP => {
                                self.add(b_start, start + cur + (*op).size as u64, (*op).jump, u64::MAX, BlockType::Normal, block_score);
                                b_start = start + cur + (*op).size as u64;
                                block_score = 0;
                            }
                            R_ANAL_OP_TYPE_UCALL => {
                                // unknown call (i.e. register)
                                // more investigation to do
                            }
                            R_ANAL_OP_TYPE_TRAP => {
                                if b_start < start + cur {
                                    self.add(b_start, start + cur , u64::MAX, u64::MAX, BlockType::Normal, block_score);
                                }
                                b_start = start + cur + (*op).size as u64;
                                block_score = 0;
                            }
                            R_ANAL_OP_TYPE_UNK => {
                                block_score -= 10;
                            }
                            R_ANAL_OP_TYPE_ILL => {
                                block_score -= 10;
                            }

                            _ => {
                                if (*op).ptr != u64::MAX as i64 {
                                    if offset_inside((*op).ptr as u64) {
                                        self.data_ref.entry(start + cur).or_insert((*op).ptr as u64);
                                    }
                                }
                            }
                        }

                        if (*op).size == 0 {
                            cur += 1;
                        } else {
                            cur += (*op).size as u64;
                        }
                        r_anal_op_free (op);
                    }
                }
            }
        }

        self.blocks.sort();
        let mut result: Vec<BasicBlock> = Vec::new();

        while let Some(mut block) = self.blocks.pop() {
            if block.jump != u64::MAX {
                self.jumps.entry(block.jump).or_insert(block.start);
            }

            if block.fail != u64::MAX {
                self.jumps.entry(block.fail).or_insert(block.start);
            }

            if let Some(last) = self.blocks.last_mut() {
                // check if the next block is the same as this one (multiple inserts)
                if (*last).start == block.start && block.end == u64::MAX {
                    continue;
                }

                if block.start == (*last).start && (*last).end == u64::MAX {
                    (*last).end = block.end;
                    (*last).jump = block.jump;
                    (*last).fail = block.fail;
                    continue;
                }

                // altering two blocks if the (*last) one points with its
                // start address into the block before
                if block.end < u64::MAX && (*last).start < block.end && (*last).start > block.start {
                    if (*last).jump == u64::MAX {
                        (*last).jump = block.jump;
                    }
                    if (*last).fail == u64::MAX {
                        (*last).fail = block.fail;
                    }
                    (*last).end = block.end;
                    block.end = (*last).start;
                    block.jump = (*last).start;
                    block.fail = u64::MAX;
                    (*last).block_type = block.block_type;
                }

            }

            match block.block_type {
                BlockType::Call => {
                    self.calls.push(block.start);
                    result.push(block);
                }
                BlockType::Normal => {
                    result.push(block);
                }

                _ => {}
            }
        }

        for block in &result {
            self.block_map.insert(block.start, *block);
        }

        self.blocks.append(&mut result);
        self.blocks.sort();
        for block in &self.blocks {
            // check if the block is reached by another one
            if !self.jumps.contains_key(&block.start) {
                // go through all basic blocks of the current function
                let mut fcn = Function::new(block.start);
                fcn.add_block(*block);
                let mut offsets: Vec<u64> = Vec::new();
                offsets.push(block.jump);
                offsets.push(block.fail);

                while !offsets.is_empty() {
                    let off = offsets.pop().unwrap();
                    if self.block_map.contains_key(&off) {
                        let current_block = self.block_map.get(&off).unwrap();
                        if !fcn.contains_block(current_block.jump) {
                            offsets.push(current_block.jump);
                        }

                        if !fcn.contains_block(current_block.fail) {
                            offsets.push(current_block.fail);
                        }

                        fcn.add_block(*current_block);
                    }
                }

                if fcn.get_score() == 0 {
                    self.functions.push(fcn);
                }
            }
        }

        for (from, to) in &self.call_ref {
            unsafe {
                let s: String = format!("axC {} {}\n", to, from);
                r_cons_strcat(s.as_ptr() as *const c_char); // CString::new(s).unwrap().as_ptr());
            }
        }

        for (from, to) in &self.data_ref {
            unsafe {
                let s: String = format!("axd {} {}\n", to, from);
                r_cons_strcat(s.as_ptr() as *const c_char); // CString::new(s).unwrap().as_ptr());
                // r_cons_strcat(CString::new(s).unwrap().as_ptr());
            }
        }
    }

    pub fn block_count(&mut self) -> usize {
        self.blocks.len()
    }

    pub fn fn_count(&mut self) -> usize {
        self.calls.len()
    }

    pub fn print_info(&mut self) {
        stderr!("{: <10} direct calls", self.calls.len());
        stderr!("{: <10} basic blocks", self.blocks.len());
        stderr!("{: <10} possible functions", self.functions.len());
        stderr!("{: <10} call refs", self.call_ref.len());
        stderr!("{: <10} data refs", self.data_ref.len());
    }
}

#[cfg(test)]
mod tests {
}
