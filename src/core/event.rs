/*
pub struct EventEmitter<U, T: FnOnce(U)> {
    listener: Vec<T>
}

impl<U, T> EventEmitter<U, T> where T : FnOnce(U){
    pub fn new () -> Self {
        EventEmitter {
            listener: Vec::new()
        }
    }

    pub fn on (&mut self, listener: T) {
        self.listener.push(listener);
    }

    pub fn emit(&self, event: &U) {

    }

}*/

pub trait On<T> {
    fn on (&self, event: &T);
}

pub struct EventEmitter<T> {
    listeners: Vec<Box<On<T>>>
}

impl<T> EventEmitter<T> {
    pub fn new () -> Self {
        EventEmitter {
            listeners: Vec::new()
        }
    }

    pub fn bind (&mut self, listener: Box<On<T>>) {
        self.listeners.push(listener);
    }

    pub fn emit (&self, event: &T) {
        for listener in self.listeners.iter() {
            listener.on(event);
        }
    }
}