//! **eva-hands** — руки Евы на рабочей машине.
//!
//! Одно долгое соединение вместо ssh на каждый чих, сырые байты вместо
//! base64 через `cat`, честные коды отказов вместо пустого ответа. Что
//! умеют руки — в [`proto::Op`]; как этим пользоваться — [`Hands`].
//!
//! Транспорт — stdio ssh-сессии: демон на той стороне запускается как
//! `eva-hands serve`, доступ решают те же ключи, что и раньше, а нового
//! открытого порта не появляется.

pub mod client;
pub mod limits;
pub mod ops;
pub mod proto;
pub mod server;

pub use client::{Error, Greeting, Hands, Output, SshTarget};
pub use limits::Limits;
pub use proto::{Code, Entry, Failure, Kind};
