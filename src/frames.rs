//! Wire-level framing. One JSON document per line

use tokio::io::AsyncBufReadExt;
use zeevum_protocol::{MAX_LINE_BYTES, ServerMsg, encode};

/// Serializes a server message into a wire frame, JSON plus a trailing newline
pub fn frame(msg: &ServerMsg) -> String {
    encode(msg).expect("ServerMsg serialization cannot fail")
}

/// Reads a single newline terminated frame
///
/// Frames longer than [`MAX_LINE_BYTES`] are rejected with
/// [`std::io::ErrorKind::InvalidData`], which closes the connection
pub async fn read_frame<S>(reader: &mut S) -> std::io::Result<String>
where
    S: AsyncBufReadExt + Unpin,
{
    let mut out: Vec<u8> = Vec::with_capacity(512);

    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(String::from_utf8_lossy(&out).into_owned());
        }

        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            out.extend_from_slice(&available[..=pos]);
            reader.consume(pos + 1);
            return if out.len() > MAX_LINE_BYTES {
                Err(too_long())
            } else {
                Ok(String::from_utf8_lossy(&out).into_owned())
            };
        }

        out.extend_from_slice(available);
        let used = available.len();
        reader.consume(used);

        if out.len() > MAX_LINE_BYTES {
            return Err(too_long());
        }
    }
}

fn too_long() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "frame exceeds MAX_LINE_BYTES",
    )
}
