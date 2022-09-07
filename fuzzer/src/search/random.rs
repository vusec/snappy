use super::SearchHandler;
use rand::prelude::*;

pub struct RandomSearch<'a> {
    handler: SearchHandler<'a>,
}

impl<'a> RandomSearch<'a> {
    pub fn new(handler: SearchHandler<'a>) -> Self {
        Self { handler }
    }

    pub fn run<R: Rng + ?Sized>(&mut self, rng: &mut R) {
        let mut input = self.handler.get_f_input();
        let orig_input_val = input.get_value();
        loop {
            if self.handler.is_stopped_or_skip() {
                break;
            }
            input.assign(&orig_input_val);
            input.randomize_all(rng);
            self.handler.execute_cond(&input);
        }
    }
}
