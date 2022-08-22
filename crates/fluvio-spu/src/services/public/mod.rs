mod api_versions;
mod produce_handler;
mod fetch_handler;
mod offset_request;
mod offset_update;
mod stream_fetch;

#[cfg(test)]
mod tests;
mod conn_context;

use std::fmt::Debug;
use std::io::Error;
use std::marker::PhantomData;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::StreamExt;
use tracing::{debug, info, instrument, trace};

use fluvio_auth::Authorization;
use fluvio_service::{call_service, ConnectInfo, FluvioApiServer, FluvioService};
use fluvio_socket::{FluvioSocket, SocketError};
use fluvio_spu_schema::server::SpuServerApiKey;
use fluvio_spu_schema::server::SpuServerRequest;
use fluvio_storage::ReplicaStorage;
use fluvio_types::event::StickyEvent;

use crate::core::DefaultSharedGlobalContext;
use crate::services::auth::{AuthServiceContext, SpuAuthContext};

use self::api_versions::handle_api_version_request;
use self::conn_context::ConnectionContext;
use self::fetch_handler::handle_fetch_request;
use self::offset_request::handle_offset_request;
use self::offset_update::handle_offset_update;
use self::produce_handler::handle_produce_request;
use self::stream_fetch::{publishers::StreamPublishers, StreamFetchHandler};

#[derive(Debug)]
pub struct PublicServiceWithAuth<A, S> {
    data: PhantomData<A>,
    storage: PhantomData<S>,
}

impl<A, S> PublicServiceWithAuth<A, S> {
    pub fn new() -> Self {
        PublicServiceWithAuth { data: PhantomData, storage: PhantomData }
    }
}

#[async_trait]
impl<A, S> FluvioService for PublicServiceWithAuth<A, S>
    where
        A: Authorization + Sync + Send,
        <A as Authorization>::Context: Send + Sync,
        S: ReplicaStorage,
{
    type Context = SpuAuthContext<A, S>;
    type Request = SpuServerRequest;

    #[instrument(skip(self, ctx))]
    async fn respond(
        self: Arc<Self>,
        ctx: Self::Context,
        mut socket: FluvioSocket,
        _connection: ConnectInfo,
    ) -> Result<(), SocketError> {
        let auth_context = ctx
            .auth
            .create_auth_context(&mut socket)
            .await
            .map_err(|err| {
                let io_error: Error = err.into();
                io_error
            })?;

        debug!(?auth_context);
        let service_context = Arc::new(AuthServiceContext::new(
            ctx.global_ctx.clone(),
            auth_context,
        ));

        let (sink, mut stream) = socket.split();

        let mut shared_sink = sink.as_shared();
        let api_stream = stream.api_stream::<SpuServerRequest, SpuServerApiKey>();
        let shutdown = StickyEvent::shared();
        let mut event_stream = api_stream.take_until(shutdown.listen_pinned());
        let mut conn_ctx = ConnectionContext::new();

        loop {
            let event = event_stream.next().await;
            match event {
                Some(Ok(req_message)) => {
                    debug!(%req_message,"received");
                    trace!(
                        "conn: {}, received request: {:#?}",
                        shared_sink.id(),
                        req_message
                    );
                    match req_message {
                        SpuServerRequest::ApiVersionsRequest(request) => call_service!(
                            request,
                            handle_api_version_request(request),
                            shared_sink,
                            "ApiVersionsRequest"
                        ),
                        // NOTE: As a POC only tackling the handle_produce_request request handler
                        SpuServerRequest::ProduceRequest(request) => call_service!(
                            request,
                            handle_produce_request(request, &service_context),
                            shared_sink,
                            "ProduceRequest"
                        ),
                        SpuServerRequest::FileFetchRequest(request) => {
                            handle_fetch_request(request, service_context.global_ctx.clone(), shared_sink.clone())
                                .await?
                        }
                        SpuServerRequest::FetchOffsetsRequest(request) => call_service!(
                            request,
                            handle_offset_request(request, service_context.global_ctx.clone()),
                            shared_sink,
                            "FetchOffsetsRequest"
                        ),
                        SpuServerRequest::FileStreamFetchRequest(request) => {
                            StreamFetchHandler::start(
                                request,
                                service_context.global_ctx.clone(),
                                &mut conn_ctx,
                                shared_sink.clone(),
                                shutdown.clone(),
                            )
                                .await?;
                        }
                        SpuServerRequest::UpdateOffsetsRequest(request) => call_service!(
                            request,
                            handle_offset_update(request, &mut conn_ctx),
                            shared_sink,
                            "UpdateOffsetsRequest"
                        ),
                    }
                }
                Some(Err(e)) => {
                    debug!(
                        sink_id = shared_sink.id(),
                        "Error decoding message, ending connection: {}", e
                    );
                    break;
                }
                None => {
                    debug!(sink_id = shared_sink.id(), "No content, end of connection",);
                    break;
                }
            }
        }

        shutdown.notify();
        debug!("service terminated");
        Ok(())
    }
}

pub fn create_public_server_with_auth<A, S>(
    ctx: SpuAuthContext<A, S>,
) -> SpuPublicServerWithAuth<A, S>
    where
    A: Authorization + Sync + Send + Debug + 'static,
    SpuAuthContext<A, S>: Clone + Debug,
    <A as Authorization>::Context: Send + Sync,
    S: ReplicaStorage,
{
    let public_ep_addr = ctx.global_ctx.config().public_socket_addr().to_owned();
    debug!("starting public api service");
    info!(
        spu_id = ctx.global_ctx.local_spu_id(),
        %public_ep_addr,
        "Starting SPU public service:",
    );

    FluvioApiServer::new(public_ep_addr, ctx.global_ctx, PublicServiceWithAuth::new())
}

pub(crate) type SpuPublicServerWithAuth<A, S> =
FluvioApiServer<SpuServerRequest, SpuServerApiKey, DefaultSharedGlobalContext, PublicServiceWithAuth<A, S>>;

pub(crate) type SpuPublicServer =
FluvioApiServer<SpuServerRequest, SpuServerApiKey, DefaultSharedGlobalContext, PublicService>;

pub fn create_public_server(
    addr: String,
    ctx: DefaultSharedGlobalContext,
) -> SpuPublicServer {
    info!(
        spu_id = ctx.local_spu_id(),
        %addr,
        "Starting SPU public service:",
    );

    FluvioApiServer::new(addr, ctx, PublicService::new())
}

#[derive(Debug)]
pub struct PublicService {
    _0: (), // Prevent construction
}

impl PublicService {
    pub fn new() -> Self {
        PublicService { _0: () }
    }
}

#[async_trait]
impl FluvioService for PublicService {
    type Request = SpuServerRequest;
    type Context = DefaultSharedGlobalContext;

    #[instrument(skip(self, context))]
    async fn respond(
        self: Arc<Self>,
        context: DefaultSharedGlobalContext,
        socket: FluvioSocket,
        _connection: ConnectInfo,
    ) -> Result<(), SocketError> {
        let (sink, mut stream) = socket.split();

        let mut shared_sink = sink.as_shared();
        let api_stream = stream.api_stream::<SpuServerRequest, SpuServerApiKey>();
        let shutdown = StickyEvent::shared();
        let mut event_stream = api_stream.take_until(shutdown.listen_pinned());
        let mut conn_ctx = ConnectionContext::new();

        loop {
            let event = event_stream.next().await;
            match event {
                Some(Ok(req_message)) => {
                    debug!(%req_message,"received");
                    trace!(
                        "conn: {}, received request: {:#?}",
                        shared_sink.id(),
                        req_message
                    );
                    match req_message {
                        SpuServerRequest::ApiVersionsRequest(request) => call_service!(
                            request,
                            handle_api_version_request(request),
                            shared_sink,
                            "ApiVersionsRequest"
                        ),
                        SpuServerRequest::ProduceRequest(request) => call_service!(
                            request,
                            handle_produce_request(request, context.clone()),
                            shared_sink,
                            "ProduceRequest"
                        ),
                        SpuServerRequest::FileFetchRequest(request) => {
                            handle_fetch_request(request, context.clone(), shared_sink.clone())
                                .await?
                        }
                        SpuServerRequest::FetchOffsetsRequest(request) => call_service!(
                            request,
                            handle_offset_request(request, context.clone()),
                            shared_sink,
                            "FetchOffsetsRequest"
                        ),
                        SpuServerRequest::FileStreamFetchRequest(request) => {
                            StreamFetchHandler::start(
                                request,
                                context.clone(),
                                &mut conn_ctx,
                                shared_sink.clone(),
                                shutdown.clone(),
                            )
                            .await?;
                        }
                        SpuServerRequest::UpdateOffsetsRequest(request) => call_service!(
                            request,
                            handle_offset_update(request, &mut conn_ctx),
                            shared_sink,
                            "UpdateOffsetsRequest"
                        ),
                    }
                }
                Some(Err(e)) => {
                    debug!(
                        sink_id = shared_sink.id(),
                        "Error decoding message, ending connection: {}", e
                    );
                    break;
                }
                None => {
                    debug!(sink_id = shared_sink.id(), "No content, end of connection",);
                    break;
                }
            }
        }

        shutdown.notify();
        debug!("service terminated");
        Ok(())
    }
}
