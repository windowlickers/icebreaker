//! Overlap buffer for detecting secrets that span chunk boundaries.

use bytes::{Bytes, BytesMut};

/// Default overlap size (256 bytes).
pub const DEFAULT_OVERLAP_SIZE: usize = 256;

/// A buffer that maintains overlap between chunks to detect patterns
/// that might span chunk boundaries.
#[derive(Debug)]
pub struct OverlapBuffer {
    /// The overlap from the previous chunk.
    overlap: BytesMut,

    /// Maximum overlap size to keep.
    overlap_size: usize,
}

impl Default for OverlapBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_OVERLAP_SIZE)
    }
}

impl OverlapBuffer {
    /// Creates a new overlap buffer with the specified overlap size.
    #[must_use]
    pub fn new(overlap_size: usize) -> Self {
        Self {
            overlap: BytesMut::with_capacity(overlap_size),
            overlap_size,
        }
    }

    /// Processes a chunk and returns the searchable region.
    ///
    /// The searchable region includes the overlap from the previous chunk
    /// concatenated with the current chunk. This ensures patterns that span
    /// chunk boundaries are detected.
    ///
    /// # Arguments
    ///
    /// * `chunk` - The current chunk of data.
    /// * `is_last` - Whether this is the last chunk.
    ///
    /// # Returns
    ///
    /// The searchable region (overlap + current chunk for non-last chunks,
    /// or the remaining data for the last chunk).
    pub fn process(&mut self, chunk: &Bytes, is_last: bool) -> Bytes {
        if is_last {
            // For the last chunk, return everything including overlap
            let mut result = BytesMut::with_capacity(self.overlap.len() + chunk.len());
            result.extend_from_slice(&self.overlap);
            result.extend_from_slice(chunk);
            self.overlap.clear();
            return result.freeze();
        }

        // Build searchable region: overlap + current chunk
        let mut searchable = BytesMut::with_capacity(self.overlap.len() + chunk.len());
        searchable.extend_from_slice(&self.overlap);
        searchable.extend_from_slice(chunk);

        // Update overlap for next iteration
        self.overlap.clear();
        if chunk.len() >= self.overlap_size {
            // Take last `overlap_size` bytes from chunk
            self.overlap
                .extend_from_slice(&chunk[chunk.len() - self.overlap_size..]);
        } else if self.overlap.capacity() > 0 {
            // Chunk is smaller than overlap size, keep as much as we can
            let combined_len = searchable.len();
            if combined_len >= self.overlap_size {
                self.overlap
                    .extend_from_slice(&searchable[combined_len - self.overlap_size..]);
            } else {
                self.overlap.extend_from_slice(&searchable);
            }
        }

        searchable.freeze()
    }

    /// Resets the buffer, clearing any stored overlap.
    pub fn reset(&mut self) {
        self.overlap.clear();
    }

    /// Returns true if the buffer has overlap data.
    #[must_use]
    pub fn has_overlap(&self) -> bool {
        !self.overlap.is_empty()
    }

    /// Returns the current overlap size.
    #[must_use]
    pub fn current_overlap_len(&self) -> usize {
        self.overlap.len()
    }
}

/// A scanner that uses overlap buffering to find patterns in a stream.
#[derive(Debug)]
pub struct StreamScanner {
    buffer: OverlapBuffer,
    patterns: Vec<Vec<u8>>,
}

impl StreamScanner {
    /// Creates a new stream scanner with the given patterns.
    #[must_use]
    pub fn new(patterns: Vec<Vec<u8>>) -> Self {
        // Overlap size should be at least as large as the longest pattern
        let max_pattern_len = patterns.iter().map(|p| p.len()).max().unwrap_or(0);
        let overlap_size = max_pattern_len.max(DEFAULT_OVERLAP_SIZE);

        Self {
            buffer: OverlapBuffer::new(overlap_size),
            patterns,
        }
    }

    /// Scans a chunk for any patterns.
    ///
    /// Returns `true` if any pattern is found in the searchable region.
    pub fn scan_chunk(&mut self, chunk: &Bytes, is_last: bool) -> bool {
        let searchable = self.buffer.process(chunk, is_last);

        for pattern in &self.patterns {
            if contains_pattern(&searchable, pattern) {
                return true;
            }
        }

        false
    }

    /// Resets the scanner state.
    pub fn reset(&mut self) {
        self.buffer.reset();
    }

    /// Adds a pattern to scan for.
    pub fn add_pattern(&mut self, pattern: Vec<u8>) {
        self.patterns.push(pattern);
    }
}

/// Simple pattern search (could be optimized with Aho-Corasick for multiple patterns).
fn contains_pattern(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }

    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overlap_buffer_simple() {
        let mut buffer = OverlapBuffer::new(4);

        // First chunk: "hello"
        let chunk1 = Bytes::from("hello");
        let searchable1 = buffer.process(&chunk1, false);
        assert_eq!(&searchable1[..], b"hello");

        // Buffer should have last 4 bytes as overlap
        assert_eq!(buffer.current_overlap_len(), 4);

        // Second chunk: "world"
        let chunk2 = Bytes::from("world");
        let searchable2 = buffer.process(&chunk2, false);
        // Should be "ello" (overlap, last 4 bytes of "hello") + "world"
        assert_eq!(&searchable2[..], b"elloworld");
    }

    #[test]
    fn test_overlap_buffer_last_chunk() {
        let mut buffer = OverlapBuffer::new(4);

        let chunk1 = Bytes::from("hello");
        let _ = buffer.process(&chunk1, false);

        let chunk2 = Bytes::from("!");
        let searchable = buffer.process(&chunk2, true);
        // Should include overlap (last 4 bytes of "hello" = "ello") + final chunk
        assert_eq!(&searchable[..], b"ello!");
    }

    #[test]
    fn test_overlap_buffer_pattern_across_boundary() {
        let mut buffer = OverlapBuffer::new(4);
        let pattern = b"loworld";

        // First chunk ends with "hel" + "lo"
        let chunk1 = Bytes::from("hello");
        let searchable1 = buffer.process(&chunk1, false);

        // Pattern not complete yet
        assert!(!contains_pattern(&searchable1, pattern));

        // Second chunk starts with "world"
        let chunk2 = Bytes::from("world");
        let searchable2 = buffer.process(&chunk2, false);

        // Now we should find "loworld" spanning the boundary
        assert!(contains_pattern(&searchable2, pattern));
    }

    #[test]
    fn test_stream_scanner() {
        let patterns = vec![b"secret".to_vec(), b"password".to_vec()];
        let mut scanner = StreamScanner::new(patterns);

        // No match
        assert!(!scanner.scan_chunk(&Bytes::from("hello world"), false));

        // Match in chunk
        assert!(scanner.scan_chunk(&Bytes::from("my secret key"), false));
    }

    #[test]
    fn test_stream_scanner_boundary_match() {
        let patterns = vec![b"SECRET".to_vec()];
        let mut scanner = StreamScanner::new(patterns);

        // "SEC" at end of first chunk
        assert!(!scanner.scan_chunk(&Bytes::from("...SEC"), false));

        // "RET" at start of second chunk - should match when combined with overlap
        assert!(scanner.scan_chunk(&Bytes::from("RET..."), false));
    }

    #[test]
    fn test_contains_pattern() {
        assert!(contains_pattern(b"hello world", b"world"));
        assert!(contains_pattern(b"hello", b"hello"));
        assert!(contains_pattern(b"test", b""));
        assert!(!contains_pattern(b"hello", b"world"));
        assert!(!contains_pattern(b"hi", b"hello"));
    }
}
