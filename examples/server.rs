extern crate quinn;

fn main() {
    quinn::Server::new("0.0.0.0", 4433).run();
}
