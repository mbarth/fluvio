pub use common::*;

pub mod basic;

mod common {
    use std::fmt::Debug;
    use std::sync::Arc;

    use crate::core::{GlobalContext, SharedGlobalContext};

    /// SPU context with authorization
    /// auth is trait object which contains auth policy
    #[derive(Clone, Debug)]
    pub struct SpuAuthContext<A, S> {
        pub global_ctx: SharedGlobalContext<S>,
        pub auth: Arc<A>,
    }

    impl<A, S> SpuAuthContext<A, S> {
        pub fn new(global_ctx: SharedGlobalContext<S>, auth: Arc<A>) -> Self {
            Self { global_ctx, auth }
        }
    }

    /// Auth Service Context, this hold individual context that is enough enforce auth
    /// for this service context
    #[derive(Debug, Clone)]
    pub struct AuthServiceContext<AC, S> {
        pub global_ctx: GlobalContext<S>,
        pub auth: AC,
    }

    impl<AC, S> AuthServiceContext<AC, S> {
        pub fn new(global_ctx: GlobalContext<S>, auth: AC) -> Self {
            Self { global_ctx, auth }
        }
    }
}
