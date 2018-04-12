extern crate quinn;

fn main() {
    quinn::bind("0.0.0.0", 4433);
}
