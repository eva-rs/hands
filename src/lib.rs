//! **eva-hands** — руки Евы на рабочей машине.
//!
//! Одно долгое соединение вместо процесса на каждый чих, сырые байты вместо
//! base64 через `cat`, честные коды отказов вместо пустого ответа. Что
//! умеют руки — в [`proto::Op`]; как этим пользоваться — [`Hands`].
//!
//! Демон слушает свой порт и пускает только владельца приватного ключа из
//! своего `authorized_keys`: ssh-демон на машине не нужен, ssh-бинарь у
//! клиента — тоже. Криптография не наша — это реализация протокола SSH
//! (`russh`), внутри канала которой текут наши кадры.

pub mod client;
pub mod limits;
pub mod ops;
pub mod proto;
pub mod server;
pub mod transport;

pub use client::{Error, Greeting, Hands, Output};
pub use limits::Limits;
pub use proto::{Code, Entry, Failure, Kind};
pub use transport::Endpoint;
