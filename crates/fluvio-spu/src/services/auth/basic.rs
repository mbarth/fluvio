use std::sync::Arc;

use tracing::instrument;
use async_trait::async_trait;
pub use policy::BasicRbacPolicy;

use fluvio_auth::{AuthContext, Authorization, TypeAction, InstanceAction, AuthError};
use fluvio_controlplane_metadata::extended::ObjectType;
use fluvio_auth::x509::X509Identity;

#[derive(Debug, Clone)]
pub struct BasicAuthorization {
    policy: Arc<BasicRbacPolicy>,
}

impl BasicAuthorization {
    pub fn new(policy: BasicRbacPolicy) -> Self {
        Self {
            policy: Arc::new(policy),
        }
    }
}

#[async_trait]
impl Authorization for BasicAuthorization {
    type Context = BasicAuthContext;

    #[instrument(level = "trace", skip(self, socket))]
    async fn create_auth_context(
        &self,
        socket: &mut fluvio_socket::FluvioSocket,
    ) -> Result<Self::Context, AuthError> {
        let identity = X509Identity::create_from_connection(socket).await?;
        Ok(BasicAuthContext {
            identity,
            policy: self.policy.clone(),
        })
    }
}

#[derive(Debug)]
pub struct BasicAuthContext {
    identity: X509Identity,
    policy: Arc<BasicRbacPolicy>,
}

#[async_trait]
impl AuthContext for BasicAuthContext {
    async fn allow_type_action(
        &self,
        ty: ObjectType,
        action: TypeAction,
    ) -> Result<bool, AuthError> {
        self.policy
            .evaluate(action.into(), ty, None, &self.identity)
            .await
    }

    /// check if specific instance of spec can be deleted
    async fn allow_instance_action(
        &self,
        _ty: ObjectType,
        _action: InstanceAction,
        _key: &str,
    ) -> Result<bool, AuthError> {
        Ok(true)
    }
}

/// basic policy module
/// does impl substitution
mod policy {

    use std::fs::read;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::convert::TryFrom;

    use tracing::debug;
    use serde::{Serialize, Deserialize};

    use fluvio_auth::{AuthError, TypeAction, InstanceAction};
    use fluvio_auth::x509::X509Identity;

    use super::ObjectType;

    type Role = String;

    #[derive(Debug, Clone, PartialEq, Hash, Eq, Deserialize, Serialize)]
    pub enum Action {
        Create,
        Read,
        Update,
        Delete,
        All,
    }

    impl From<TypeAction> for Action {
        fn from(action: TypeAction) -> Self {
            match action {
                TypeAction::Create => Action::Create,
                TypeAction::Read => Action::Read,
            }
        }
    }

    impl From<InstanceAction> for Action {
        fn from(action: InstanceAction) -> Self {
            match action {
                InstanceAction::Delete => Action::Delete,
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
    pub struct BasicRbacPolicy(pub HashMap<Role, HashMap<ObjectType, Vec<Action>>>);

    impl From<HashMap<Role, HashMap<ObjectType, Vec<Action>>>> for BasicRbacPolicy {
        fn from(map: HashMap<Role, HashMap<ObjectType, Vec<Action>>>) -> Self {
            Self(map)
        }
    }

    impl TryFrom<PathBuf> for BasicRbacPolicy {
        type Error = std::io::Error;
        fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
            debug!("reading basic policy: {:#?}", path);
            let file = read(path)?;
            let policy: BasicRbacPolicy = serde_json::from_slice(&file)?;
            Ok(policy)
        }
    }

    impl BasicRbacPolicy {
        pub async fn evaluate(
            &self,
            action: Action,
            object_type: ObjectType,
            _instance: Option<&str>,
            identity: &X509Identity,
        ) -> Result<bool, AuthError> {
            //   let (action,object,_instance) = request;
            // For each scope provided in the identity,
            // check if there is a match;
            let is_allowed = identity.scopes().iter().any(|scope| {
                self.0
                    .get(scope)
                    .map(|objects| {
                        objects
                            .get(&object_type)
                            .map(|actions| {
                                actions.iter().any(|permission| {
                                    permission == &action || permission == &Action::All
                                })
                            })
                            .unwrap_or(false)
                    })
                    .unwrap_or(false)
            });

            Ok(is_allowed)
        }
    }

    impl Default for BasicRbacPolicy {
        // default only allows the `Root` role to have full permissions;
        fn default() -> Self {
            let mut root_policy = HashMap::new();

            root_policy.insert(ObjectType::Spu, vec![Action::All]);
            root_policy.insert(ObjectType::CustomSpu, vec![Action::All]);
            root_policy.insert(ObjectType::SpuGroup, vec![Action::All]);
            root_policy.insert(ObjectType::Topic, vec![Action::All]);
            root_policy.insert(ObjectType::Partition, vec![Action::All]);
            root_policy.insert(ObjectType::TableFormat, vec![Action::All]);

            let mut policy = HashMap::new();

            policy.insert(String::from("Root"), root_policy);

            Self(policy)
        }
    }
}