use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream as TokioTcpStream;

pub(super) type DownstreamReadHalf = Box<dyn AsyncRead + Send + Unpin + 'static>;
pub(super) type DownstreamWriteHalf = Box<dyn AsyncWrite + Send + Unpin + 'static>;

pub(crate) struct DownstreamStream {
    read_half: DownstreamReadHalf,
    write_half: DownstreamWriteHalf,
    write_coalesce_bytes: Option<usize>,
}

impl DownstreamStream {
    pub(crate) fn from_tcp_stream(stream: TokioTcpStream, write_coalesce_bytes: Option<usize>) -> Self {
        let (read_half, write_half): (OwnedReadHalf, OwnedWriteHalf) = stream.into_split();
        Self {
            read_half: Box::new(read_half),
            write_half: Box::new(write_half),
            write_coalesce_bytes,
        }
    }

    pub(crate) fn from_halves(
        read_half: DownstreamReadHalf,
        write_half: DownstreamWriteHalf,
        write_coalesce_bytes: Option<usize>,
    ) -> Self {
        Self {
            read_half,
            write_half,
            write_coalesce_bytes,
        }
    }

    pub(crate) fn split(self) -> (DownstreamReadHalf, DownstreamWriteHalf, Option<usize>) {
        (self.read_half, self.write_half, self.write_coalesce_bytes)
    }
}
