use async_compression::tokio::bufread::{
	BrotliDecoder, BrotliEncoder, GzipDecoder, GzipEncoder, ZlibDecoder, ZlibEncoder, ZstdDecoder,
	ZstdEncoder,
};
use bytes::Bytes;
use futures_util::TryStreamExt;
use headers::{ContentEncoding, Header};
use http_body::Body;
use http_body_util::BodyExt;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};
use tokio_util::io::{ReaderStream, StreamReader};

const GZIP: &str = "gzip";
const DEFLATE: &str = "deflate";
const BR: &str = "br";
const ZSTD: &str = "zstd";

/// Errors that can occur during compression/decompression operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("unsupported content encoding")]
	UnsupportedEncoding,
	#[error("body exceeded buffer limit")]
	LimitExceeded,
	#[error("decompression failed: {0}")]
	Io(#[from] std::io::Error),
	#[error("body read error: {0}")]
	Body(#[from] axum_core::Error),
}

impl From<Error> for axum_core::Error {
	fn from(e: Error) -> Self {
		axum_core::Error::new(e)
	}
}

enum EncodingDecision {
	None,
	Single(&'static str),
	Multiple,
	Unsupported,
}

/// Detects which single supported encoding is present in the Content-Encoding header.
///
/// Returns `Single(encoding)` if exactly one supported encoding is present.
/// Returns `None` if no encoding (or only `identity`) is present.
/// Returns `Multiple` if multiple encodings are present (chain decoding unsupported).
/// Returns `Unsupported` if an unknown encoding is present.
fn detect_encoding(ce: &ContentEncoding) -> EncodingDecision {
	let mut values = Vec::new();
	ce.encode(&mut values);
	let Some(value) = values.first() else {
		return EncodingDecision::None;
	};
	let Ok(raw) = value.to_str() else {
		return EncodingDecision::Unsupported;
	};

	let mut supported_count = 0;
	let mut single_supported = None;
	let mut has_unknown = false;

	for token in raw.split(',') {
		let token = token.trim();
		if token.is_empty() {
			continue;
		}
		if token.eq_ignore_ascii_case("identity") {
			// identity is a no-op encoding (RFC 9110 §8.4.1), skip it so
			// "identity, gzip" is treated the same as "gzip".
			continue;
		}

		if token.eq_ignore_ascii_case(GZIP) {
			supported_count += 1;
			single_supported = Some(GZIP);
		} else if token.eq_ignore_ascii_case(DEFLATE) {
			supported_count += 1;
			single_supported = Some(DEFLATE);
		} else if token.eq_ignore_ascii_case(BR) {
			supported_count += 1;
			single_supported = Some(BR);
		} else if token.eq_ignore_ascii_case(ZSTD) {
			supported_count += 1;
			single_supported = Some(ZSTD);
		} else {
			has_unknown = true;
		}
	}

	if has_unknown {
		return EncodingDecision::Unsupported;
	}

	// Strict policy: identity-only => None; >1 supported => Multiple.
	if supported_count == 0 {
		return EncodingDecision::None;
	}

	if supported_count > 1 {
		return EncodingDecision::Multiple;
	}

	match single_supported {
		Some(enc) => EncodingDecision::Single(enc),
		None => EncodingDecision::Unsupported,
	}
}

/// Decompresses an HTTP body stream, returning a new body that yields decompressed chunks.
///
/// Use this for streaming responses (SSE, large files) where you can't buffer the entire body.
/// If encoding is None or identity, returns the body unchanged.
/// If encoding is unsupported or multi-encoded, returns an error.
pub fn decompress_body<B>(
	body: B,
	encoding: Option<&ContentEncoding>,
) -> Result<(axum_core::body::Body, Option<&'static str>), Error>
where
	B: Body<Data = Bytes> + Send + Unpin + 'static,
	B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
	match encoding {
		None => Ok((axum_core::body::Body::new(body), None)),
		Some(ce) => match detect_encoding(ce) {
			EncodingDecision::Single(enc) => {
				decompress_body_with_encoding(body, enc).map(|b| (b, Some(enc)))
			},
			EncodingDecision::None => Ok((axum_core::body::Body::new(body), None)),
			EncodingDecision::Multiple | EncodingDecision::Unsupported => Err(Error::UnsupportedEncoding),
		},
	}
}

fn decompress_body_with_encoding<B>(body: B, encoding: &str) -> Result<axum_core::body::Body, Error>
where
	B: Body + Send + Unpin + 'static,
	B::Data: Send,
	B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
	let byte_stream = body.into_data_stream().map_err(std::io::Error::other);
	let stream_reader = BufReader::new(StreamReader::new(byte_stream));

	let decoder: Box<dyn AsyncRead + Unpin + Send> = match encoding {
		GZIP => Box::new(GzipDecoder::new(stream_reader)),
		DEFLATE => Box::new(ZlibDecoder::new(stream_reader)),
		BR => Box::new(BrotliDecoder::new(stream_reader)),
		ZSTD => Box::new(ZstdDecoder::new(stream_reader)),
		_ => return Err(Error::UnsupportedEncoding),
	};

	Ok(axum_core::body::Body::from_stream(ReaderStream::new(
		decoder,
	)))
}

pub async fn to_bytes_with_decompression(
	body: axum_core::body::Body,
	encoding: Option<&ContentEncoding>,
	limit: usize,
) -> Result<(Option<&'static str>, Bytes), Error> {
	match encoding {
		None => {
			// No encoding - use optimized direct body read
			Ok((None, read_body_with_limit(body, limit).await?))
		},
		Some(ce) => match detect_encoding(ce) {
			EncodingDecision::Single(enc) => Ok((Some(enc), decode_body(body, enc, limit).await?)),
			EncodingDecision::None => Ok((None, read_body_with_limit(body, limit).await?)),
			EncodingDecision::Multiple | EncodingDecision::Unsupported => Err(Error::UnsupportedEncoding),
		},
	}
}

pub async fn encode_body(body: &[u8], encoding: &str) -> Result<Bytes, axum_core::Error> {
	let reader = BufReader::new(body);

	let encoder: Box<dyn tokio::io::AsyncRead + Unpin + Send> = match encoding {
		GZIP => Box::new(GzipEncoder::new(reader)),
		DEFLATE => Box::new(ZlibEncoder::new(reader)),
		BR => Box::new(BrotliEncoder::new(reader)),
		ZSTD => Box::new(ZstdEncoder::new(reader)),
		_ => return Err(Error::UnsupportedEncoding.into()),
	};

	// Preallocate assuming ~50% compression (it can grow if we are wrong)
	read_to_bytes(encoder, body.len() / 2)
		.await
		.map_err(Into::into)
}

async fn decode_body<B>(body: B, encoding: &str, limit: usize) -> Result<Bytes, Error>
where
	B: Body<Data = Bytes> + Send + Unpin + 'static,
	B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
	// Compose streaming decompression with optimized body reading
	let decompressed = decompress_body_with_encoding(body, encoding)?;
	read_body_with_limit(decompressed, limit).await
}

async fn read_to_bytes<R>(mut reader: R, initial_capacity: usize) -> Result<Bytes, Error>
where
	R: AsyncRead + Unpin,
{
	let mut buffer = bytes::BytesMut::with_capacity(initial_capacity);
	loop {
		let n = reader.read_buf(&mut buffer).await?;
		if n == 0 {
			break;
		}
	}
	Ok(buffer.freeze())
}

async fn read_body_with_limit(body: axum_core::body::Body, limit: usize) -> Result<Bytes, Error> {
	crate::http::read_body_with_limit(body, limit)
		.await
		.map_err(map_body_error)
}

fn map_body_error(err: axum_core::Error) -> Error {
	if is_length_limit_error(&err) {
		Error::LimitExceeded
	} else {
		Error::Body(err)
	}
}

fn is_length_limit_error(err: &axum_core::Error) -> bool {
	use std::error::Error as _;

	err
		.source()
		.is_some_and(|source| source.is::<http_body_util::LengthLimitError>())
}
