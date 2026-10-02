use zeevum_protocol::{ServerMsg, encode};

/// The frame reader lives in the protocol crate, where the format it reads
/// is defined. Re-exported so that call sites keep a single import.
pub use zeevum_protocol::read_frame;

pub fn frame(msg: &ServerMsg) -> String {
    encode(msg).expect("ServerMsg serialization cannot fail")
}
