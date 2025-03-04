use std::default::Default;
use std::fmt;
use std::fmt::{Debug, Display};
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, instrument, info};

use dataplane::api::RequestMessage;
use dataplane::api::Request;
use dataplane::versions::{ApiVersions, ApiVersionsRequest, ApiVersionsResponse};
use fluvio_socket::{AsyncResponse, SocketError};
use fluvio_socket::{FluvioSocket, SharedMultiplexerSocket};
use fluvio_future::net::{DomainConnector, DefaultDomainConnector};
use fluvio_future::retry::retry;

use crate::FluvioError;

/// Frame with request and response
pub(crate) trait SerialFrame: Display {
    /// client config
    fn config(&self) -> &ClientConfig;
}

/// This sockets knows about support versions
/// Version information are automatically  insert into request
pub struct VersionedSocket {
    socket: FluvioSocket,
    config: Arc<ClientConfig>,
    versions: Versions,
}

impl fmt::Display for VersionedSocket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "config {}", self.config)
    }
}

impl SerialFrame for VersionedSocket {
    fn config(&self) -> &ClientConfig {
        &self.config
    }
}

impl VersionedSocket {
    /// connect to end point and retrieve versions
    #[instrument(skip(socket, config))]
    pub async fn connect(
        mut socket: FluvioSocket,
        config: Arc<ClientConfig>,
    ) -> Result<Self, FluvioError> {
        // now get versions
        // Query for API versions

        let mut req_msg = RequestMessage::new_request(ApiVersionsRequest {
            client_version: crate::built_info::PKG_VERSION.into(),
            client_os: crate::built_info::CFG_OS.into(),
            client_arch: crate::built_info::CFG_TARGET_ARCH.into(),
        });
        req_msg.get_mut_header().set_client_id(&config.client_id);

        debug!("querying versions");
        let response: ApiVersionsResponse = (socket.send(&req_msg).await?).response;
        let versions = Versions::new(response);

        debug!("versions: {:#?}", versions);

        Ok(Self {
            socket,
            config,
            versions,
        })
    }

    pub fn split(self) -> (FluvioSocket, Arc<ClientConfig>, Versions) {
        (self.socket, self.config, self.versions)
    }
}

/// Connection Config to any client
pub struct ClientConfig {
    addr: String,
    client_id: String,
    connector: DomainConnector,
    pub(crate) use_spu_local_address: bool,
}

impl Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ClientConfig {{ addr: {}, client_id: {} }}",
            self.addr, self.client_id
        )
    }
}

impl fmt::Display for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "addr {}", self.addr)
    }
}

impl From<String> for ClientConfig {
    fn from(addr: String) -> Self {
        Self::with_addr(addr)
    }
}

impl ClientConfig {
    pub fn new<S: Into<String>>(
        addr: S,
        connector: DomainConnector,
        use_spu_local_address: bool,
    ) -> Self {
        Self {
            addr: addr.into(),
            client_id: "fluvio".to_owned(),
            connector,
            use_spu_local_address,
        }
    }

    pub fn with_addr(addr: String) -> Self {
        Self::new(addr, Box::new(DefaultDomainConnector::default()), false)
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// set client id
    #[allow(unused)]
    pub fn set_client_id<S>(mut self, id: S) -> Self
    where
        S: Into<String>,
    {
        self.client_id = id.into();
        self
    }

    pub fn set_addr(&mut self, domain: String) {
        self.addr = domain
    }

    #[instrument(skip(self))]
    pub async fn connect(self) -> Result<VersionedSocket, FluvioError> {
        debug!(add = %self.addr, "try connection to");
        let socket =
            FluvioSocket::connect_with_connector(&self.addr, self.connector.as_ref()).await?;
        info!(add = %self.addr, "connect to socket");
        VersionedSocket::connect(socket, Arc::new(self)).await
    }

    /// create new config with prefix add to domain, this is useful for SNI
    #[instrument(skip(self))]
    pub fn with_prefix_sni_domain(&self, prefix: &str) -> Self {
        let new_domain = format!("{}.{}", prefix, self.connector.domain());
        debug!(sni_domain = %new_domain);
        let connector = self.connector.new_domain(new_domain);

        Self {
            addr: self.addr.clone(),
            client_id: self.client_id.clone(),
            connector,
            use_spu_local_address: self.use_spu_local_address,
        }
    }
}

/// wrap around versions
#[derive(Clone, Debug)]
pub struct Versions {
    api_versions: ApiVersions,
    platform_version: semver::Version,
}

impl Versions {
    pub fn new(version_response: ApiVersionsResponse) -> Self {
        Self {
            api_versions: version_response.api_keys,
            platform_version: version_response.platform_version.to_semver(),
        }
    }

    /// Tells the platform version reported by the SC
    ///
    /// The platform version refers to the value in the VERSION
    /// file at the time the SC was compiled.
    pub fn platform_version(&self) -> &semver::Version {
        &self.platform_version
    }

    /// Given an API key, it returns max_version. None if not found
    pub fn lookup_version(&self, api_key: u16, client_version: i16) -> Option<i16> {
        for version in &self.api_versions {
            if version.api_key == api_key as i16 {
                return Some(std::cmp::min(version.max_version, client_version));
            }
        }
        None
    }
}

/// Connection that perform request/response
pub struct VersionedSerialSocket {
    socket: SharedMultiplexerSocket,
    config: Arc<ClientConfig>,
    versions: Versions,
}

impl fmt::Display for VersionedSerialSocket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "config: {}, {:?}", self.config, self.socket)
    }
}
unsafe impl Send for VersionedSerialSocket {}

impl VersionedSerialSocket {
    pub fn new(
        socket: SharedMultiplexerSocket,
        config: Arc<ClientConfig>,
        versions: Versions,
    ) -> Self {
        Self {
            socket,
            config,
            versions,
        }
    }

    pub fn versions(&self) -> &Versions {
        &self.versions
    }

    /// send and wait for reply serially
    #[instrument(level = "trace", skip(self, request))]
    pub async fn send_receive<R>(&self, request: R) -> Result<R::Response, SocketError>
    where
        R: Request + Send + Sync,
    {
        let req_msg = self.new_request(
            request,
            self.versions
                .lookup_version(R::API_KEY, R::DEFAULT_API_VERSION),
        );

        // send request & save response
        self.socket.send_and_receive(req_msg).await
    }

    /// send and do not wait for reply
    #[instrument(level = "trace", skip(self, request))]
    pub async fn send_async<R>(&self, request: R) -> Result<AsyncResponse<R>, SocketError>
    where
        R: Request + Send + Sync,
    {
        let req_msg = self.new_request(
            request,
            self.versions
                .lookup_version(R::API_KEY, R::DEFAULT_API_VERSION),
        );

        // send request & get a Future that resolves to response
        self.socket.send_async(req_msg).await
    }

    /// send, wait for reply and retry if failed
    #[instrument(level = "trace", skip(self, request))]
    pub async fn send_receive_with_retry<R, I>(
        &self,
        request: R,
        retries: I,
    ) -> Result<R::Response, SocketError>
    where
        R: Request + Send + Sync + Clone,
        I: IntoIterator<Item = Duration> + Debug + Send,
    {
        let req_msg = self.new_request(
            request,
            self.versions
                .lookup_version(R::API_KEY, R::DEFAULT_API_VERSION),
        );

        // send request & retry it if result is Err
        retry(retries, || self.socket.send_and_receive(req_msg.clone())).await
    }

    /// create new request based on version
    #[instrument(level = "trace", skip(self, request, version))]
    fn new_request<R>(&self, request: R, version: Option<i16>) -> RequestMessage<R>
    where
        R: Request + Send,
    {
        let mut req_msg = RequestMessage::new_request(request);
        req_msg
            .get_mut_header()
            .set_client_id(&self.config().client_id);

        if let Some(ver) = version {
            req_msg.get_mut_header().set_api_version(ver);
        }
        req_msg
    }
}

impl SerialFrame for VersionedSerialSocket {
    fn config(&self) -> &ClientConfig {
        &self.config
    }
}

#[cfg(test)]
mod test {
    use dataplane::versions::ApiVersionKey;

    use super::ApiVersionsResponse;
    use super::Versions;

    #[test]
    fn test_version_lookup() {
        let mut response = ApiVersionsResponse::default();

        response.api_keys.push(ApiVersionKey {
            api_key: 1000,
            min_version: 0,
            max_version: 10,
        });

        let versions = Versions::new(response);

        // None if api_key not found
        assert_eq!(versions.lookup_version(0, 10), None);

        // Must use max version of the client
        (0..10).for_each(|i| assert_eq!(versions.lookup_version(1000, i), Some(i)));

        // Since max_version of the client is larger than the max_version of the server, should use the max_version of the server
        (10..12).for_each(|i| assert_eq!(versions.lookup_version(1000, i), Some(10)));
    }
}
