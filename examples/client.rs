extern crate quinn;

fn main() {
    quinn::connect("mozquic.ducksong.com", 4433);
}
