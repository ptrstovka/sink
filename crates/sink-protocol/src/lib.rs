//! Shared, versioned contracts for the Sink control link.
//!
//! The control WebSocket starts with one JSON [`ClientHello`] and one JSON
//! [`ServerHello`]. After acceptance, both peers treat binary WebSocket messages
//! as a continuous byte stream and run yamux over [`MessageIo`]. Public HTTP
//! exchanges each use a fresh yamux stream, so application traffic is never
//! replayed by the control protocol.

mod handshake;
mod message_io;
mod subdomain;

pub use handshake::{
    ClientHello, HandshakeError, RejectCode, ServerHello, SessionAccepted, SessionRejected,
};
pub use message_io::MessageIo;
pub use subdomain::{Subdomain, SubdomainError};

/// Current wire-contract version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Reserved HTTP path used on the `connect` host.
pub const CONTROL_PATH: &str = "/_sink/connect";

/// Only this many bytes are accepted for either JSON handshake message.
pub const MAX_HANDSHAKE_BYTES: usize = 16 * 1024;

/// Upper bound used by runtimes for one binary WebSocket message.
pub const MAX_TRANSPORT_MESSAGE_BYTES: usize = 64 * 1024;

/// Product-reserved DNS label for the authenticated control endpoint.
pub const RESERVED_CONNECT_SUBDOMAIN: &str = "connect";

/// The server opens one yamux stream per public request or upgraded connection.
pub const YAMUX_STREAMS_ARE_SINGLE_EXCHANGE: bool = true;
