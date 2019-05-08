use crate::Settings;

pub struct Connection {
    settings: Settings,
}

impl Connection {
    pub fn new(settings: Settings) -> Self {
        Self { settings }
    }
}
