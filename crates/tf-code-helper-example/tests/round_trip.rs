//! End-to-end smoke test for the generated rpc-rust output:
//!   - Stand up a CodeHelperServer implementation backed by an in-memory
//!     transport pair.
//!   - Call it through the generated CodeHelperClient.
//!   - Assert the unary + server-streaming paths both round-trip.
//!
//! This is the only caller of `tf-schema codegen --target rpc-rust` that
//! actually compiles the output, so it is the gate that catches codegen
//! regressions on the Rust side.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tf_types::rpc::{AllowAllEnforcer, RpcClient, RpcContext, RpcError, RpcServer, RpcTransport};
use tf_types::session::SessionFrame;
use tokio::sync::mpsc;

use tf_code_helper_example::{
    register_code_helper, CodeHelperClient, CodeHelperServer, FetchFileRequest, FetchFileResponse,
    StreamDirectoryRequest, StreamDirectoryResponse, StreamDirectoryResponse_Kind,
};

type Listener = Arc<dyn Fn(SessionFrame) + Send + Sync>;

struct InMemoryTransport {
    peer_listeners: Arc<Mutex<Vec<Listener>>>,
    our_listeners: Arc<Mutex<Vec<Listener>>>,
}

impl RpcTransport for InMemoryTransport {
    fn send(&self, frame: SessionFrame) {
        for l in self.peer_listeners.lock().unwrap().clone() {
            l(frame.clone());
        }
    }
    fn on_frame(&self, listener: Arc<dyn Fn(SessionFrame) + Send + Sync>) {
        self.our_listeners.lock().unwrap().push(listener);
    }
}

fn wire_pair() -> (Arc<InMemoryTransport>, Arc<InMemoryTransport>) {
    let a_ours: Arc<Mutex<Vec<Listener>>> = Arc::new(Mutex::new(Vec::new()));
    let b_ours: Arc<Mutex<Vec<Listener>>> = Arc::new(Mutex::new(Vec::new()));
    let a = Arc::new(InMemoryTransport {
        peer_listeners: Arc::new(Mutex::new(Vec::new())),
        our_listeners: a_ours.clone(),
    });
    let b = Arc::new(InMemoryTransport {
        peer_listeners: Arc::new(Mutex::new(Vec::new())),
        our_listeners: b_ours.clone(),
    });
    {
        let b_ours = b_ours.clone();
        a.peer_listeners.lock().unwrap().push(Arc::new(move |f| {
            for l in b_ours.lock().unwrap().clone() {
                l(f.clone());
            }
        }));
    }
    {
        let a_ours = a_ours.clone();
        b.peer_listeners.lock().unwrap().push(Arc::new(move |f| {
            for l in a_ours.lock().unwrap().clone() {
                l(f.clone());
            }
        }));
    }
    (a, b)
}

struct DemoServer;

#[async_trait]
impl CodeHelperServer for DemoServer {
    async fn fetch_file(
        &self,
        req: FetchFileRequest,
        _ctx: RpcContext,
    ) -> Result<FetchFileResponse, RpcError> {
        Ok(FetchFileResponse {
            path: req.path.clone(),
            contents: format!("generated contents of {}", req.path),
            size: Some(req.path.len() as i64),
        })
    }

    async fn stream_directory(
        &self,
        _req: StreamDirectoryRequest,
        _ctx: RpcContext,
        tx: mpsc::UnboundedSender<Result<StreamDirectoryResponse, RpcError>>,
    ) {
        let _ = tx.send(Ok(StreamDirectoryResponse {
            name: "a.txt".into(),
            kind: StreamDirectoryResponse_Kind::File,
            size: Some(10),
        }));
        let _ = tx.send(Ok(StreamDirectoryResponse {
            name: "b.txt".into(),
            kind: StreamDirectoryResponse_Kind::File,
            size: Some(20),
        }));
        let _ = tx.send(Ok(StreamDirectoryResponse {
            name: "sub".into(),
            kind: StreamDirectoryResponse_Kind::Dir,
            size: Some(0),
        }));
    }
}

#[tokio::test]
async fn unary_round_trip_through_generated_client() {
    let (client_t, server_t) = wire_pair();
    let server = RpcServer::new(
        server_t.clone(),
        "tf:actor:agent:example.com/srv",
        Arc::new(AllowAllEnforcer),
    );
    register_code_helper(&server, Arc::new(DemoServer));

    let rpc_client = Arc::new(RpcClient::new(
        client_t.clone(),
        "tf:actor:human:example.com/user",
    ));
    let client = CodeHelperClient::new(rpc_client);

    let resp = client
        .fetch_file(&FetchFileRequest {
            path: "README.md".into(),
        })
        .await
        .unwrap();
    assert_eq!(resp.path, "README.md");
    assert_eq!(resp.contents, "generated contents of README.md");
    assert_eq!(resp.size, Some(9));
}

#[tokio::test]
async fn server_stream_delivers_entries_through_generated_client() {
    let (client_t, server_t) = wire_pair();
    let server = RpcServer::new(
        server_t.clone(),
        "tf:actor:agent:example.com/srv",
        Arc::new(AllowAllEnforcer),
    );
    register_code_helper(&server, Arc::new(DemoServer));

    let rpc_client = Arc::new(RpcClient::new(
        client_t.clone(),
        "tf:actor:human:example.com/user",
    ));
    let client = CodeHelperClient::new(rpc_client);

    let mut rx = client.stream_directory(&StreamDirectoryRequest { path: ".".into() });
    let mut names = Vec::new();
    while let Some(item) = rx.recv().await {
        let entry = item.expect("stream item ok");
        names.push(entry.name.clone());
    }
    assert_eq!(names, vec!["a.txt", "b.txt", "sub"]);
}
