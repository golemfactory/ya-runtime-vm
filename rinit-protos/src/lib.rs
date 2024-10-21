pub mod rinit {
    pub mod api {
        include!(concat!(env!("OUT_DIR"), "/rinit.api.rs"));
    }
}
