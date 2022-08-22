use std::fmt::Debug;
use std::sync::Arc;

use fluvio_auth::Authorization;
use fluvio_storage::{FileReplica, ReplicaStorage};

use crate::config::{SpuConfig, SpuOpt};
use crate::control_plane::ScDispatcher;
use crate::core::DefaultSharedGlobalContext;
use crate::core::GlobalContext;
use crate::services::auth::basic::{BasicAuthorization, BasicRbacPolicy};
use crate::services::auth::SpuAuthContext;
use crate::services::create_internal_server;
use crate::services::internal::InternalApiServer;
use crate::services::public::{create_public_server, create_public_server_with_auth, SpuPublicServer, SpuPublicServerWithAuth};

type FileReplicaContext = GlobalContext<FileReplica>;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn main_loop(opt: SpuOpt) {
    use std::time::Duration;

    use sysinfo::{System, SystemExt};
    use tracing::info;

    use fluvio_future::task::run_block_on;
    use fluvio_future::timer::sleep;
    // parse configuration (program exits on error)
    let (config, tls_acceptor_option) = opt.process_spu_cli_or_exit();
    let (spu_config, auth_policy) = config;

    println!("starting spu server (id:{})", spu_config.id);

    let mut sys = System::new_all();
    sys.refresh_all();
    info!(version = crate::VERSION, "Platform");
    info!(commit = env!("GIT_HASH"), "Git");
    info!(name = ?sys.name(),"System");
    info!(kernel = ?sys.kernel_version(),"System");
    info!(os_version = ?sys.long_os_version(),"System");
    info!(core_count = ?sys.physical_core_count(),"System");
    info!(total_memory = sys.total_memory(), "System");
    info!(available_memory = sys.available_memory(), "System");
    info!(uptime = sys.uptime(), "Uptime in secs");

    run_block_on(async move {
        if let Some(auth) = auth_policy {
            let (_ctx, internal_server, public_server) =
                create_services_with_auth(spu_config.clone(), auth, true, true);

            let _public_shutdown = internal_server.unwrap().run();
            let _private_shutdown = public_server.unwrap().run();
        } else {
            let (_ctx, internal_server, public_server) =
                create_services(spu_config.clone(), true, true);

            let _public_shutdown = internal_server.unwrap().run();
            let _private_shutdown = public_server.unwrap().run();
        }

        if let Some(tls_config) = tls_acceptor_option {
            proxy::start_proxy(spu_config, tls_config).await;
        }

        println!("SPU Version: {} started successfully", VERSION);

        // infinite loop
        loop {
            sleep(Duration::from_secs(60)).await;
        }
    });
}

/// create server and spin up services, but don't run server
pub fn create_services(
    local_spu: SpuConfig,
    internal: bool,
    public: bool,
) -> (
    DefaultSharedGlobalContext,
    Option<InternalApiServer>,
    Option<SpuPublicServer>,
) {
    let ctx = FileReplicaContext::new_shared_context(local_spu);

    let public_ep_addr = ctx.config().public_socket_addr().to_owned();
    let private_ep_addr = ctx.config().private_socket_addr().to_owned();

    let public_server = if public {
        Some(create_public_server(public_ep_addr, ctx.clone()))
    } else {
        None
    };

    let internal_server = if internal {
        Some(create_internal_server(private_ep_addr, ctx.clone()))
    } else {
        None
    };

    let sc_dispatcher = ScDispatcher::new(ctx.clone());
    sc_dispatcher.run();

    (ctx, internal_server, public_server)
}

/// create server and spin up services, but don't run server
pub fn create_services_with_auth<A, S>(
    local_spu: SpuConfig,
    auth_policy: BasicRbacPolicy,
    internal: bool,
    public: bool,
) -> (
    DefaultSharedGlobalContext,
    Option<InternalApiServer>,
    Option<SpuPublicServerWithAuth<A, S>>,
) where
    A: Authorization + Sync + Send + Debug + 'static,
    SpuPublicServerWithAuth<A, S>: Debug,
    <A as Authorization>::Context: Send + Sync,
    S: ReplicaStorage,
{
    let ctx = FileReplicaContext::new_shared_context(local_spu);

    let private_ep_addr = ctx.config().private_socket_addr().to_owned();

    let public_server = if public {
        Some(create_public_server_with_auth(SpuAuthContext::new(
            ctx.clone(),
            Arc::new(BasicAuthorization::new(auth_policy)),
        )))
    } else {
        None
    };

    let internal_server = if internal {
        Some(create_internal_server(private_ep_addr, ctx.clone()))
    } else {
        None
    };

    let sc_dispatcher = ScDispatcher::new(ctx.clone());
    sc_dispatcher.run();

    (ctx, internal_server, public_server)
}

mod proxy {
    use std::process;

    use fluvio_future::openssl::TlsAcceptor;
    use flv_tls_proxy::{
        start as proxy_start, start_with_authenticator as proxy_start_with_authenticator,
    };
    use flv_util::print_cli_err;
    use tracing::info;

    use fluvio_auth::x509::X509Authenticator;

    use crate::config::SpuConfig;

    pub async fn start_proxy(config: SpuConfig, acceptor: (TlsAcceptor, String)) {
        let (tls_acceptor, proxy_addr) = acceptor;
        let target = config.public_endpoint;
        info!("starting TLS proxy: {}", proxy_addr);

        let result = if let Some(x509_auth_scopes) = config.x509_auth_scopes {
            let authenticator = Box::new(X509Authenticator::new(&x509_auth_scopes));
            proxy_start_with_authenticator(&proxy_addr, tls_acceptor, target, authenticator).await
        } else {
            proxy_start(&proxy_addr, tls_acceptor, target).await
        };

        if let Err(err) = result {
            print_cli_err!(err);
            process::exit(-1);
        } else {
            info!("TLS started successfully");
            println!("TLS proxy started");
        }
    }
}
