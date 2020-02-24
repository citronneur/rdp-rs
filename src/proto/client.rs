use proto::x224;
pub struct RdpClient<S> {
    x224 : x224::Client<S>
}

impl<S> RdpClient<S> {
    pub fn new(x224: x224::Client<S>) -> Self {
        RdpClient {
            x224
        }
    }
}