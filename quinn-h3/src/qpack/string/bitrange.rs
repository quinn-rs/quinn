#[derive(Debug, PartialEq, Clone)]
pub struct BitRange {
    pub byte: u32,
    pub bit: u32,
    pub count: u32
}


impl BitRange {

    pub fn new() -> BitRange {
        BitRange { byte: 0, bit: 0, count: 0 }
    }

    pub fn forwards(&mut self, step: u32) {
        self.bit += self.count;
        
        self.byte += self.bit / 8;
        self.bit %= 8;
        
        self.count = step;
    }

    pub fn join(&mut self) {
        self.forwards(0);
    }

    pub fn byte_boundary(&self) -> BitRange {
        BitRange {
            byte: self.byte,
            bit: self.bit,
            count: 8 - (self.bit % 8)
        }
    }

}
