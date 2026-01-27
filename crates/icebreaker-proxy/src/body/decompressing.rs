//! Decompressing body wrapper for handling compressed HTTP responses.
//!
//! This module provides a streaming decompression wrapper that supports common
//! HTTP compression encodings (gzip, deflate, brotli, zstd). It decompresses
//! response bodies before they reach the secret scanner, ensuring secrets
//! can be detected even in compressed responses.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_compression::tokio::bufread::{BrotliDecoder, GzipDecoder, ZlibDecoder, ZstdDecoder};
use bytes::Bytes;
use futures_util::ready;
use http_body::{Body, Frame};
use pin_project_lite::pin_project;
use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};

/// Maximum decompressed size to prevent decompression bombs (100 MB).
const MAX_DECOMPRESSED_SIZE: u64 = 100 * 1024 * 1024;

/// Size of chunks to read from decompressors.
const DECOMPRESS_CHUNK_SIZE: usize = 8192;

pin_project! {
    /// A body wrapper that decompresses response content.
    ///
    /// Supports gzip, deflate (zlib), brotli, and zstd compression.
    /// Falls back to passthrough for uncompressed or unsupported encodings.
    ///
    /// Fields:
    /// - `inner`: The inner decompression variant
    /// - `decompressed_bytes`: Total bytes decompressed so far
    /// - `completed`: Whether the body has completed
    pub struct DecompressingBody<B>
    where
        B: Body,
    {
        #[pin]
        inner: DecompressInner<B>,
        decompressed_bytes: u64,
        completed: bool,
    }
}

pin_project! {
    #[project = DecompressInnerProj]
    enum DecompressInner<B>
    where
        B: Body,
    {
        Identity {
            #[pin]
            inner: B,
        },
        Gzip {
            #[pin]
            inner: WrapBody<GzipDecoder<BodyReader<B>>>,
        },
        Deflate {
            #[pin]
            inner: WrapBody<ZlibDecoder<BodyReader<B>>>,
        },
        Brotli {
            #[pin]
            inner: WrapBody<BrotliDecoder<BodyReader<B>>>,
        },
        Zstd {
            #[pin]
            inner: WrapBody<ZstdDecoder<BodyReader<B>>>,
        },
    }
}

impl<B> DecompressingBody<B>
where
    B: Body,
{
    /// Creates a body that passes through without decompression.
    pub fn identity(inner: B) -> Self {
        Self {
            inner: DecompressInner::Identity { inner },
            decompressed_bytes: 0,
            completed: false,
        }
    }
}

impl<B> DecompressingBody<B>
where
    B: Body<Data = Bytes> + Send + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    /// Creates a gzip-decompressing body.
    pub fn gzip(inner: B) -> Self {
        let reader = BodyReader::new(inner);
        let decoder = GzipDecoder::new(reader);
        Self {
            inner: DecompressInner::Gzip {
                inner: WrapBody::new(decoder),
            },
            decompressed_bytes: 0,
            completed: false,
        }
    }

    /// Creates a deflate (zlib)-decompressing body.
    pub fn deflate(inner: B) -> Self {
        let reader = BodyReader::new(inner);
        let decoder = ZlibDecoder::new(reader);
        Self {
            inner: DecompressInner::Deflate {
                inner: WrapBody::new(decoder),
            },
            decompressed_bytes: 0,
            completed: false,
        }
    }

    /// Creates a brotli-decompressing body.
    pub fn brotli(inner: B) -> Self {
        let reader = BodyReader::new(inner);
        let decoder = BrotliDecoder::new(reader);
        Self {
            inner: DecompressInner::Brotli {
                inner: WrapBody::new(decoder),
            },
            decompressed_bytes: 0,
            completed: false,
        }
    }

    /// Creates a zstd-decompressing body.
    pub fn zstd(inner: B) -> Self {
        let reader = BodyReader::new(inner);
        let decoder = ZstdDecoder::new(reader);
        Self {
            inner: DecompressInner::Zstd {
                inner: WrapBody::new(decoder),
            },
            decompressed_bytes: 0,
            completed: false,
        }
    }
}

/// Error type for decompression operations.
#[derive(Debug, thiserror::Error)]
pub enum DecompressError {
    /// The decompressed size exceeded the maximum allowed.
    #[error("decompressed size exceeded maximum of {MAX_DECOMPRESSED_SIZE} bytes")]
    SizeLimitExceeded,

    /// An I/O error occurred during decompression.
    #[error("decompression I/O error: {0}")]
    Io(#[from] io::Error),

    /// An error from the underlying body.
    #[error("body error: {0}")]
    Body(Box<dyn std::error::Error + Send + Sync>),
}

impl<B> Body for DecompressingBody<B>
where
    B: Body<Data = Bytes> + Send + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();

        if *this.completed {
            return Poll::Ready(None);
        }

        match this.inner.project() {
            DecompressInnerProj::Identity { inner } => match ready!(inner.poll_frame(cx)) {
                Some(Ok(frame)) => Poll::Ready(Some(Ok(frame))),
                Some(Err(e)) => Poll::Ready(Some(Err(e.into()))),
                None => {
                    *this.completed = true;
                    Poll::Ready(None)
                }
            },
            DecompressInnerProj::Gzip { inner } => {
                poll_decompressing_frame(inner, cx, this.decompressed_bytes, this.completed)
            }
            DecompressInnerProj::Deflate { inner } => {
                poll_decompressing_frame(inner, cx, this.decompressed_bytes, this.completed)
            }
            DecompressInnerProj::Brotli { inner } => {
                poll_decompressing_frame(inner, cx, this.decompressed_bytes, this.completed)
            }
            DecompressInnerProj::Zstd { inner } => {
                poll_decompressing_frame(inner, cx, this.decompressed_bytes, this.completed)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.completed
    }

    fn size_hint(&self) -> http_body::SizeHint {
        // We can't know the decompressed size ahead of time
        http_body::SizeHint::default()
    }
}

/// Result type for decompression frame polling.
type DecompressFrameResult =
    Poll<Option<Result<Frame<Bytes>, Box<dyn std::error::Error + Send + Sync>>>>;

/// Polls a decompressing body implementation for the next frame.
fn poll_decompressing_frame<R>(
    inner: Pin<&mut WrapBody<R>>,
    cx: &mut Context<'_>,
    decompressed_bytes: &mut u64,
    completed: &mut bool,
) -> DecompressFrameResult
where
    R: AsyncRead,
{
    match ready!(inner.poll_frame(cx)) {
        Some(Ok(frame)) => {
            if let Some(data) = frame.data_ref() {
                *decompressed_bytes = decompressed_bytes.saturating_add(data.len() as u64);
                if *decompressed_bytes > MAX_DECOMPRESSED_SIZE {
                    *completed = true;
                    return Poll::Ready(Some(Err(Box::new(DecompressError::SizeLimitExceeded))));
                }
            }
            Poll::Ready(Some(Ok(frame)))
        }
        Some(Err(e)) => {
            *completed = true;
            Poll::Ready(Some(Err(e)))
        }
        None => {
            *completed = true;
            Poll::Ready(None)
        }
    }
}

pin_project! {
    /// Converts an `AsyncRead` back into a `Body`.
    ///
    /// Fields:
    /// - `reader`: The async reader to read from
    /// - `buffer`: Buffer for reading chunks
    struct WrapBody<R> {
        #[pin]
        reader: R,
        buffer: Vec<u8>,
    }
}

impl<R> WrapBody<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: vec![0u8; DECOMPRESS_CHUNK_SIZE],
        }
    }
}

impl<R> Body for WrapBody<R>
where
    R: AsyncRead,
{
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        let mut read_buf = ReadBuf::new(this.buffer);

        match ready!(this.reader.poll_read(cx, &mut read_buf)) {
            Ok(()) => {
                let filled = read_buf.filled().len();
                if filled == 0 {
                    // EOF
                    Poll::Ready(None)
                } else {
                    let data = Bytes::copy_from_slice(&this.buffer[..filled]);
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
            }
            Err(e) => Poll::Ready(Some(Err(Box::new(DecompressError::Io(e))))),
        }
    }

    fn is_end_stream(&self) -> bool {
        false
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::default()
    }
}

pin_project! {
    /// Converts a `Body` into an `AsyncBufRead`.
    ///
    /// This buffers chunks from the body and provides them as a continuous
    /// byte stream for the decompressor to read from.
    ///
    /// Fields:
    /// - `body`: The body to read from
    /// - `chunk`: Current chunk being read
    /// - `eof`: Whether we've reached the end of the body
    /// - `error`: Stored error for later reporting
    struct BodyReader<B>
    where
        B: Body,
    {
        #[pin]
        body: B,
        chunk: Option<Bytes>,
        eof: bool,
        error: Option<Box<dyn std::error::Error + Send + Sync>>,
    }
}

impl<B> BodyReader<B>
where
    B: Body,
{
    fn new(body: B) -> Self {
        Self {
            body,
            chunk: None,
            eof: false,
            error: None,
        }
    }
}

impl<B> AsyncRead for BodyReader<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();

        // Check for stored error
        if let Some(e) = this.error.take() {
            return Poll::Ready(Err(io::Error::other(e)));
        }

        // If we have a chunk with data, read from it
        if let Some(chunk) = this.chunk {
            if !chunk.is_empty() {
                let to_read = std::cmp::min(chunk.len(), buf.remaining());
                buf.put_slice(&chunk[..to_read]);
                *chunk = chunk.slice(to_read..);
                return Poll::Ready(Ok(()));
            } else {
                *this.chunk = None;
            }
        }

        // If we've reached EOF, return empty
        if *this.eof {
            return Poll::Ready(Ok(()));
        }

        // Poll for the next frame
        match ready!(this.body.poll_frame(cx)) {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    if !data.is_empty() {
                        let to_read = std::cmp::min(data.len(), buf.remaining());
                        buf.put_slice(&data[..to_read]);
                        if to_read < data.len() {
                            *this.chunk = Some(data.slice(to_read..));
                        }
                        return Poll::Ready(Ok(()));
                    }
                }
                // Empty data frame or trailers, poll again
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Some(Err(e)) => {
                *this.eof = true;
                Poll::Ready(Err(io::Error::other(e.into())))
            }
            None => {
                *this.eof = true;
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl<B> AsyncBufRead for BodyReader<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.project();

        // Check for stored error
        if let Some(e) = this.error.take() {
            return Poll::Ready(Err(io::Error::other(e)));
        }

        // If we have a chunk, return it
        if this.chunk.as_ref().is_some_and(|c| !c.is_empty()) {
            // We just checked that chunk is Some and non-empty
            let chunk = this.chunk.as_ref().map(|c| c.as_ref());
            return Poll::Ready(Ok(chunk.unwrap_or(&[])));
        }

        // If we've reached EOF, return empty
        if *this.eof {
            return Poll::Ready(Ok(&[]));
        }

        // Poll for the next frame
        match ready!(this.body.poll_frame(cx)) {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    if !data.is_empty() {
                        *this.chunk = Some(data);
                        let chunk = this.chunk.as_ref().map(|c| c.as_ref());
                        return Poll::Ready(Ok(chunk.unwrap_or(&[])));
                    }
                }
                // Empty data frame or trailers, poll again
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Some(Err(e)) => {
                *this.eof = true;
                Poll::Ready(Err(io::Error::other(e.into())))
            }
            None => {
                *this.eof = true;
                Poll::Ready(Ok(&[]))
            }
        }
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let this = self.project();
        if let Some(chunk) = this.chunk {
            if amt >= chunk.len() {
                *this.chunk = None;
            } else {
                *chunk = chunk.slice(amt..);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};
    use std::io::Write;

    fn gzip_compress(data: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).ok();
        encoder.finish().unwrap_or_default()
    }

    fn deflate_compress(data: &[u8]) -> Vec<u8> {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).ok();
        encoder.finish().unwrap_or_default()
    }

    #[tokio::test]
    async fn test_identity_passthrough() {
        let data = b"hello world";
        let body = Full::new(Bytes::from_static(data));
        let decompressing = DecompressingBody::identity(body);

        let result = decompressing.collect().await;
        assert!(result.is_ok());
        let collected = result.ok();
        assert_eq!(
            collected.map(|c| c.to_bytes()),
            Some(Bytes::from_static(data))
        );
    }

    #[tokio::test]
    async fn test_gzip_decompression() {
        let original = b"hello world, this is some test data!";
        let compressed = gzip_compress(original);

        let body = Full::new(Bytes::from(compressed));
        let decompressing = DecompressingBody::gzip(body);

        let result = decompressing.collect().await;
        assert!(result.is_ok());
        let collected = result.ok();
        assert_eq!(
            collected.map(|c| c.to_bytes()),
            Some(Bytes::from_static(original))
        );
    }

    #[tokio::test]
    async fn test_deflate_decompression() {
        let original = b"hello world, this is some test data!";
        let compressed = deflate_compress(original);

        let body = Full::new(Bytes::from(compressed));
        let decompressing = DecompressingBody::deflate(body);

        let result = decompressing.collect().await;
        assert!(result.is_ok());
        let collected = result.ok();
        assert_eq!(
            collected.map(|c| c.to_bytes()),
            Some(Bytes::from_static(original))
        );
    }

    #[tokio::test]
    async fn test_empty_body_identity() {
        let body = Full::new(Bytes::new());
        let decompressing = DecompressingBody::identity(body);

        let result = decompressing.collect().await;
        assert!(result.is_ok());
        let collected = result.ok();
        assert_eq!(collected.map(|c| c.to_bytes()), Some(Bytes::new()));
    }

    #[tokio::test]
    async fn test_empty_gzip() {
        // Empty gzip stream
        let compressed = gzip_compress(b"");

        let body = Full::new(Bytes::from(compressed));
        let decompressing = DecompressingBody::gzip(body);

        let result = decompressing.collect().await;
        assert!(result.is_ok());
        let collected = result.ok();
        assert_eq!(collected.map(|c| c.to_bytes()), Some(Bytes::new()));
    }
}
