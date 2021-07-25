use std::u64;
use std::fmt;
use std::cmp::Ordering;

#[derive(Copy, Clone)]
pub enum BlockType {
    Trap,
    Normal,
    Jump,
    Cjump,
    Call,
}

impl fmt::Display for BlockType {
    fn fmt(&self, f: &mut  fmt::Formatter) -> fmt::Result {
        let printable = match *self {
            BlockType::Trap => "TRAP",
            BlockType::Normal => "NORMAL",
            BlockType::Jump => "JUMP",
            BlockType::Cjump => "CJUMP",
            BlockType::Call => "CALL",
        };
        write!(f, "{}", printable)
    }
}

#[derive(Copy, Clone)]
pub struct BasicBlock {
    pub start: u64,
    pub end: u64,
    pub jump: u64,
    pub fail: u64,
    pub score: i64,
    pub block_type: BlockType,
}

impl Ord for BasicBlock {
    fn cmp(&self, other: &Self) -> Ordering {
        other.start.cmp(&self.start)
    }
}

impl PartialOrd for BasicBlock {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        other.start.partial_cmp(&self.start)
    }
}

impl PartialEq for BasicBlock {
    fn eq(&self, other: &Self) -> bool {
        other.start.eq(&self.start)
    }
}

impl Eq for BasicBlock {
}

impl fmt::Display for BasicBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "s:0x{:016x}, e:0x{:016x} j:0x{:016x} f:0x{:016x} score:{} type:{}"
               , self.start, self.end, self.jump, self.fail, self.score, self.block_type)
    }
}

impl BasicBlock {
    pub fn new(start: u64, end: u64, jump: u64, fail: u64, t: BlockType, score: i64) -> BasicBlock {
        BasicBlock { start: start, end: end, jump: jump, fail: fail, block_type: t, score: score}
    }

    pub fn size(&self) -> u64 {
        self.end - self.start
    }
}
