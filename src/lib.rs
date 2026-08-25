//! Eva's hands: file and process operations on a working machine.
//!
//! Two shapes, one [`Hands`] API:
//! - [`Hands::local`] runs every operation in-process, no network.
//! - [`Hands::remote`] talks to a daemon over an encrypted channel (Noise, with
//!   a pre-shared [`Psk`]) — without the key the handshake cannot complete, so a
//!   connection is impossible.

pub mod client;
pub mod limits;
pub mod ops;
pub mod proto;
pub mod secret;
pub mod server;
pub mod session;
pub mod transport;

pub use client::{Error, FetchRequest, Fetched, Greeting, Hands, Output, copy};
pub use limits::Limits;
pub use ops::Ops;
pub use proto::{Answer, Code, Entry, Failure, Kind, Op};
pub use secret::Psk;
