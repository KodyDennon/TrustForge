use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tf_types::rpc::RpcTransport;
use tf_types::session::{
    Initiator, Responder, SessionConfig, SessionError, SessionFrame, SessionState,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, Mutex};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

#[derive(Debug, thiserror::Error)]
pub enum CarrierError {
    #[error("session error: {0}")]
    Session(#[from] SessionError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("handshake failed: {0}")]
    Handshake(String),
}

pub struct SessionEndpoint {
    session: Arc<Mutex<SessionState>>,
    tx: mpsc::UnboundedSender<SessionFrame>,
    listeners: Arc<Mutex<Vec<Arc<dyn Fn(SessionFrame) + Send + Sync>>>>,
}

impl SessionEndpoint {
    pub async fn send(&self, frame: SessionFrame) -> Result<(), CarrierError> {
        self.tx
            .send(frame)
            .map_err(|_| CarrierError::Handshake("channel closed".into()))?;
        Ok(())
    }

    pub async fn on_frame<F>(&self, f: F)
    where
        F: Fn(SessionFrame) + Send + Sync + 'static,
    {
        let mut listeners = self.listeners.lock().await;
        listeners.push(Arc::new(f));
    }

    pub async fn peer_actor(&self) -> String {
        self.session.lock().await.peer_actor.clone()
    }
}

impl RpcTransport for SessionEndpoint {
    fn send(&self, frame: SessionFrame) {
        let _ = self.tx.send(frame);
    }

    fn on_frame(&self, listener: Arc<dyn Fn(SessionFrame) + Send + Sync>) {
        // Since RpcTransport::on_frame is non-async, we have to block or use a
        // different strategy. For this adapter, we'll use a blocking lock
        // (the listeners Mutex is rarely contended).
        // Actually, we can use a std::sync::Mutex for listeners.
        let mut listeners = futures::executor::block_on(self.listeners.lock());
        listeners.push(listener);
    }
}

/// Drive the initiator side of the handshake over an async transport.
pub async fn attach_initiator<T>(
    transport: T,
    config: SessionConfig,
) -> Result<SessionEndpoint, CarrierError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut framed = Framed::new(transport, LengthDelimitedCodec::new());
    let mut initiator = Initiator::new(config);

    // 1. Send HelloI
    let hello_i = initiator.start()?;
    let hello_i_bytes = serde_json::to_vec(&hello_i)?;
    framed.send(hello_i_bytes.into()).await?;

    // 2. Receive HelloR
    let hello_r_bytes = framed
        .next()
        .await
        .ok_or_else(|| CarrierError::Handshake("peer closed during HelloR".into()))??;
    let hello_r = serde_json::from_slice(&hello_r_bytes)?;

    // 3. Process HelloR and send Auth
    let (auth, session) = initiator.process_hello_r(hello_r)?;
    let auth_bytes = serde_json::to_vec(&auth)?;
    framed.send(auth_bytes.into()).await?;

    Ok(spawn_endpoint(session, framed))
}

/// Drive the responder side of the handshake.
pub async fn attach_responder<T>(
    transport: T,
    config: SessionConfig,
) -> Result<SessionEndpoint, CarrierError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut framed = Framed::new(transport, LengthDelimitedCodec::new());
    let mut responder = Responder::new(config);

    // 1. Receive HelloI
    let hello_i_bytes = framed
        .next()
        .await
        .ok_or_else(|| CarrierError::Handshake("peer closed during HelloI".into()))??;
    let hello_i = serde_json::from_slice(&hello_i_bytes)?;

    // 2. Process HelloI and send HelloR
    let hello_r = responder.process_hello_i(hello_i)?;
    let hello_r_bytes = serde_json::to_vec(&hello_r)?;
    framed.send(hello_r_bytes.into()).await?;

    // 3. Receive Auth and establish
    let auth_bytes = framed
        .next()
        .await
        .ok_or_else(|| CarrierError::Handshake("peer closed during Auth".into()))??;
    let auth = serde_json::from_slice(&auth_bytes)?;
    let session = responder.process_auth(auth)?;

    Ok(spawn_endpoint(session, framed))
}

fn spawn_endpoint<T>(
    session: SessionState,
    mut framed: Framed<T, LengthDelimitedCodec>,
) -> SessionEndpoint
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let session = Arc::new(Mutex::new(session));
    let (tx, mut rx) = mpsc::unbounded_channel::<SessionFrame>();
    let listeners: Arc<Mutex<Vec<Arc<dyn Fn(SessionFrame) + Send + Sync>>>> =
        Arc::new(Mutex::new(Vec::new()));

    let session_inner = session.clone();
    let listeners_inner = listeners.clone();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                // Outgoing frames
                Some(frame) = rx.recv() => {
                    let mut s = session_inner.lock().await;
                    match s.encrypt(&frame) {
                        Ok(bytes) => {
                            if let Err(e) = framed.send(bytes.into()).await {
                                tracing::error!("session send error: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::error!("session encrypt error: {}", e);
                            break;
                        }
                    }
                    if matches!(frame, SessionFrame::Close { .. }) {
                        break;
                    }
                }
                // Incoming frames
                Some(result) = framed.next() => {
                    match result {
                        Ok(bytes) => {
                            let mut s = session_inner.lock().await;
                            match s.decrypt(&bytes) {
                                Ok(frame) => {
                                    let ls = listeners_inner.lock().await;
                                    for l in ls.iter() {
                                        l(frame.clone());
                                    }
                                    if matches!(frame, SessionFrame::Close { .. }) {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("session decrypt error: {}", e);
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("session read error: {}", e);
                            break;
                        }
                    }
                }
                else => break,
            }
        }
    });

    SessionEndpoint {
        session,
        tx,
        listeners,
    }
}
