use log::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
pub(crate) mod de;
mod messages;
mod packing;
mod ser;
use serde::Serializer;

pub use messages::*;

#[derive(Debug)]
pub enum Error {
    UnexpectedEof,
    Utf8Error(std::str::Utf8Error),
    IOError(std::io::Error),
    Serde(String),
    InvalidData,
    OutOfMemory,
    Todo,
    Timeout,
    Eof,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for Error {}
impl serde::ser::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Error::Serde(msg.to_string())
    }
}
impl serde::de::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Error::Serde(msg.to_string())
    }
}
impl From<std::io::Error> for Error {
    fn from(v: std::io::Error) -> Self {
        Error::IOError(v)
    }
}
impl From<std::str::Utf8Error> for Error {
    fn from(v: std::str::Utf8Error) -> Self {
        Error::Utf8Error(v)
    }
}
impl From<std::collections::TryReserveError> for Error {
    fn from(v: std::collections::TryReserveError) -> Self {
        error!("failed to allocate {} bytes", v);
        Error::OutOfMemory
    }
}

fn get_code_maxlen(code: u8) -> usize {
    match code {
        0x0e => 50 * 1024 * 1024,  // PullMD: 50 MiB
        0x10 => 200 * 1024 * 1024, // PushMD: 200 MiB
        _ => 1024 * 50,            // otherwise 50K
    }
}

pub async fn read_packet<R: AsyncRead + Unpin>(mut reader: R) -> Result<Vec<u8>, Error> {
    let mut head = [0u8; 5];
    match reader.read_exact(&mut head).await {
        Ok(_) => {},
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(Error::Eof), // client decided to disconnect...
        Err(e) => return Err(e.into()),
    }
    let code = head[4];
    let mut buf_len = [0u8; 4];
    buf_len.copy_from_slice(&head[..4]);

    let buf_len = u32::from_be_bytes(buf_len) as usize;
    if buf_len < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "payload size is too small",
        )
        .into());
    }

    let max_len = get_code_maxlen(code);

    if buf_len > max_len {
        info!("maxium size exceeded: code={}: max={}; req={}", code, max_len, buf_len);
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request length exceeded maximum limit",
        )
        .into());
    }

    // the additional byte is for the RPC code
    trace!("expecting {} bytes...", buf_len);
    let buf_len = buf_len + 1;

    let mut data = Vec::new();
    data.try_reserve_exact(buf_len)?;
    data.resize(buf_len, 0);
    data[0] = code;
    reader.read_exact(&mut data[1..]).await?;

    Ok(data)
}

async fn write_packet<W: AsyncWrite + Unpin>(mut w: W, data: &[u8]) -> Result<(), std::io::Error> {
    let buf_len: u32 = (data.len() - 1) as u32;
    let buf_len = buf_len.to_be_bytes();
    w.write_all(&buf_len).await?;
    w.write_all(data).await?;
    Ok(())
}

pub enum RpcMessage<'a> {
    Ok(()),
    Fail(RpcFail<'a>),
    Notify(RpcNotify<'a>),
    Hello(RpcHello<'a>, Option<Creds<'a>>),
    PullMetadata(PullMetadata<'a>),
    PullMetadataResult(PullMetadataResult<'a>),
    PushMetadata(PushMetadata<'a>),
    PushMetadataResult(PushMetadataResult<'a>),
    DelHistory(DelHistory<'a>),
    DelHistoryResult(DelHistoryResult),
    GetFuncHistories(GetFuncHistories<'a>),
    GetFuncHistoriesResult(GetFuncHistoriesResult<'a>),
    HelloResult(HelloResult<'a>),
}

impl<'a> serde::Serialize for RpcMessage<'a> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;

        let code = self.get_code();
        let mut tuple = serializer.serialize_tuple(2)?;

        // u8 is pushed without further encoding...
        tuple.serialize_element(&code)?;

        match self {
            RpcMessage::Ok(msg) => tuple.serialize_element(msg)?,
            RpcMessage::Fail(msg) => tuple.serialize_element(msg)?,
            RpcMessage::Notify(msg) => tuple.serialize_element(msg)?,
            RpcMessage::Hello(msg, _) => tuple.serialize_element(msg)?,
            RpcMessage::PullMetadata(msg) => tuple.serialize_element(msg)?,
            RpcMessage::PullMetadataResult(msg) => tuple.serialize_element(msg)?,
            RpcMessage::PushMetadata(msg) => tuple.serialize_element(msg)?,
            RpcMessage::PushMetadataResult(msg) => tuple.serialize_element(msg)?,
            RpcMessage::DelHistory(msg) => tuple.serialize_element(msg)?,
            RpcMessage::DelHistoryResult(msg) => tuple.serialize_element(msg)?,
            RpcMessage::GetFuncHistories(msg) => tuple.serialize_element(msg)?,
            RpcMessage::GetFuncHistoriesResult(msg) => tuple.serialize_element(msg)?,
            RpcMessage::HelloResult(msg) => tuple.serialize_element(msg)?,
        }

        tuple.end()
    }
}

impl<'a> RpcMessage<'a> {
    fn deserialize_check<T: serde::Deserialize<'a>>(payload: &'a [u8]) -> Result<T, Error> {
        let v = de::from_slice(payload)?;
        if v.1 != payload.len() {
            let bytes_remaining = crate::make_pretty_hex(&payload[v.1..]);
            trace!(
                "{} remaining bytes after deserializing {}\n{bytes_remaining}",
                payload.len() - v.1,
                std::any::type_name::<T>()
            );
        }
        Ok(v.0)
    }

    pub fn deserialize(payload: &'a [u8]) -> Result<RpcMessage<'a>, Error> {
        let msg_type = payload[0];
        let payload = &payload[1..];

        let res = match msg_type {
            0x0a => {
                if !payload.is_empty() {
                    trace!(
                        "Ok message with additional data: {} bytes: {payload:02x?}",
                        payload.len()
                    );
                }
                RpcMessage::Ok(())
            },
            0x0b => RpcMessage::Fail(Self::deserialize_check(payload)?),
            0x0c => RpcMessage::Notify(Self::deserialize_check(payload)?),
            0x0d => {
                let (hello, consumed) = de::from_slice::<messages::RpcHello>(payload)?;
                let creds = if payload.len() > consumed && hello.protocol_version > 2 {
                    let payload = &payload[consumed..];
                    let (creds, consumed) = de::from_slice::<Creds>(payload)?;
                    if payload.len() != consumed {
                        trace!("bytes remaining after HelloV2: {payload:02x?}");
                    }
                    Some(creds)
                } else {
                    if hello.protocol_version > 2 || payload.len() != consumed {
                        trace!("Unexpected Hello msg: {payload:02x?}");
                    }
                    None
                };
                RpcMessage::Hello(hello, creds)
            },
            0x0e => RpcMessage::PullMetadata(Self::deserialize_check(payload)?),
            0x0f => RpcMessage::PullMetadataResult(Self::deserialize_check(payload)?),
            0x10 => RpcMessage::PushMetadata(Self::deserialize_check(payload)?),
            0x11 => RpcMessage::PushMetadataResult(Self::deserialize_check(payload)?),
            0x18 => RpcMessage::DelHistory(Self::deserialize_check(payload)?),
            0x19 => RpcMessage::DelHistoryResult(Self::deserialize_check(payload)?),
            0x2f => RpcMessage::GetFuncHistories(Self::deserialize_check(payload)?),
            0x30 => RpcMessage::GetFuncHistoriesResult(Self::deserialize_check(payload)?),
            0x31 => RpcMessage::HelloResult(Self::deserialize_check(payload)?),
            _ => {
                trace!("got invalid message type '{:02x}'", msg_type);
                return Err(Error::InvalidData);
            },
        };

        Ok(res)
    }

    pub async fn async_write<W: AsyncWrite + Unpin>(&self, w: W) -> Result<(), Error> {
        let mut output = Vec::with_capacity(32);
        ser::to_writer(self, &mut output)?;

        write_packet(w, &output).await?;

        Ok(())
    }

    fn get_code(&self) -> u8 {
        use RpcMessage::*;

        match self {
            Ok(_) => 0x0a,
            Fail(_) => 0x0b,
            Notify(_) => 0x0c,
            Hello(..) => 0x0d,
            PullMetadata(_) => 0x0e,
            PullMetadataResult(_) => 0x0f,
            PushMetadata(_) => 0x10,
            PushMetadataResult(_) => 0x11,
            DelHistory(_) => 0x18,
            DelHistoryResult(_) => 0x19,
            GetFuncHistories(_) => 0x2f,
            GetFuncHistoriesResult(_) => 0x30,
            HelloResult(_) => 0x31,
        }
    }
}
