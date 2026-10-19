use http::HeaderValue;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::transport::stream::Socket;

pub async fn handshake(
	conn: Socket,
	dest: &str,
	auth: Option<HeaderValue>,
) -> Result<Socket, anyhow::Error> {
	let (ext, metrics, inner) = conn.into_parts();
	let mut conn = Socket::new_rewind(inner);
	// While the raw HTTP/1 usage here looks pretty sketchy, hyper itself is doing this so its probably sufficient
	// for our simple needs here.
	// If we need to add TLS (which implies ALPN negotiation, etc) then we will want to make this more robust.
	let mut buf = format!(
		"\
         CONNECT {dest} HTTP/1.1\r\n\
         Host: {dest}\r\n\
         "
	)
	.into_bytes();

	if let Some(auth) = auth {
		buf.extend_from_slice(b"Proxy-Authorization: ");
		buf.extend_from_slice(auth.as_bytes());
		buf.extend_from_slice(b"\r\n");
	}
	// headers end
	buf.extend_from_slice(b"\r\n");
	conn.write_all(&buf).await?;

	let mut buf = [0; 8192];
	let mut pos = 0;
	loop {
		let n = conn
			.read(&mut buf[pos..])
			.await
			.map_err(crate::http::Error::new)?;
		if n == 0 {
			return Err(anyhow::anyhow!("tunnel unexpected eof"));
		}
		pos += n;

		if let Some(end) = header_end(&buf[..pos]) {
			let recvd = &buf[..pos];
			if recvd.starts_with(b"HTTP/1.1 200") || recvd.starts_with(b"HTTP/1.0 200") {
				let conn = conn.keep_after(end);
				return Ok(Socket::from_rewind(ext, metrics, conn));
			} else if recvd.starts_with(b"HTTP/1.1 407") || recvd.starts_with(b"HTTP/1.0 407") {
				return Err(anyhow::anyhow!("tunnel required auth"));
			} else {
				return Err(anyhow::anyhow!("tunnel failed"));
			}
		}
		if pos == buf.len() {
			return Err(anyhow::anyhow!("headers too long"));
		}
	}
}

fn header_end(buf: &[u8]) -> Option<usize> {
	buf
		.windows(4)
		.position(|w| w == b"\r\n\r\n")
		.map(|pos| pos + 4)
}
