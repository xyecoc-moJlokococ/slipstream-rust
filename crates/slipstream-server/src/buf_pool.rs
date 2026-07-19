//! Shared buffer pool for the multi-worker demux hot path.
//!
//! Live profiling under video-upload load showed `malloc`/`free`/`memmove` high in the
//! profile; the demux thread was `to_vec()`-ing every UDP datagram into the worker channel.
//! This pool recycles `Vec<u8>` slabs so the steady-state path is copy-into-existing-capacity
//! rather than allocate-every-packet.

use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};

/// Soft cap on free list size (per pool). Extra buffers are dropped on recycle to bound RAM.
const DEFAULT_POOL_CAP: usize = 4096;
/// Don't recycle buffers that grew absurdly large (e.g. rare fallback-sized packets).
const MAX_RECYCLE_CAPACITY: usize = 8192;

#[derive(Clone)]
pub(crate) struct BufPool {
    inner: Arc<BufPoolInner>,
}

struct BufPoolInner {
    free: Mutex<Vec<Vec<u8>>>,
    /// Preferred capacity for newly allocated slabs (DNS query size).
    slab_cap: usize,
    max_free: usize,
}

impl BufPool {
    pub(crate) fn new(slab_cap: usize) -> Self {
        Self::with_capacity(slab_cap, DEFAULT_POOL_CAP)
    }

    pub(crate) fn with_capacity(slab_cap: usize, max_free: usize) -> Self {
        Self {
            inner: Arc::new(BufPoolInner {
                free: Mutex::new(Vec::with_capacity(max_free.min(256))),
                slab_cap: slab_cap.max(64),
                max_free: max_free.max(1),
            }),
        }
    }

    /// Take a buffer and fill it with `src` (reusing capacity when possible).
    pub(crate) fn copy_from(&self, src: &[u8]) -> PooledBuf {
        let mut buf = self.acquire_raw(src.len());
        buf.clear();
        buf.extend_from_slice(src);
        PooledBuf {
            buf: Some(buf),
            pool: self.clone(),
        }
    }

    /// Take an empty buffer with at least `min_len` capacity (for callers that fill later).
    pub(crate) fn take(&self, min_len: usize) -> PooledBuf {
        let mut buf = self.acquire_raw(min_len);
        buf.clear();
        PooledBuf {
            buf: Some(buf),
            pool: self.clone(),
        }
    }

    fn acquire_raw(&self, min_len: usize) -> Vec<u8> {
        let want = min_len.max(self.inner.slab_cap);
        if let Ok(mut free) = self.inner.free.lock() {
            // Prefer a buffer that already fits; otherwise take any and grow.
            if let Some(idx) = free.iter().rposition(|b| b.capacity() >= min_len) {
                return free.swap_remove(idx);
            }
            if let Some(mut buf) = free.pop() {
                if buf.capacity() < want {
                    buf.reserve(want - buf.capacity());
                }
                return buf;
            }
        }
        Vec::with_capacity(want)
    }

    fn recycle(&self, mut buf: Vec<u8>) {
        if buf.capacity() == 0 || buf.capacity() > MAX_RECYCLE_CAPACITY {
            return;
        }
        buf.clear();
        if let Ok(mut free) = self.inner.free.lock() {
            if free.len() < self.inner.max_free {
                free.push(buf);
            }
        }
    }

    #[cfg(test)]
    fn free_len(&self) -> usize {
        self.inner.free.lock().map(|g| g.len()).unwrap_or(0)
    }
}

/// `Vec<u8>` that returns to its [`BufPool`] on drop.
pub(crate) struct PooledBuf {
    buf: Option<Vec<u8>>,
    pool: BufPool,
}

impl PooledBuf {
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.buf.as_ref().map(|b| b.as_slice()).unwrap_or(&[])
    }

    /// Resize and return a mutable view of the full buffer (for TCP read_exact fill).
    pub(crate) fn as_mut_sized(&mut self, len: usize) -> &mut [u8] {
        let raw = self.buf.as_mut().expect("pooled buf present");
        raw.resize(len, 0);
        raw.as_mut_slice()
    }

    /// Detach from the pool (e.g. rare path that must own a permanent Vec).
    #[allow(dead_code)]
    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        self.buf.take().unwrap_or_default()
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            self.pool.recycle(buf);
        }
    }
}

impl Deref for PooledBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl DerefMut for PooledBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.buf
            .as_mut()
            .map(|b| b.as_mut_slice())
            .unwrap_or(&mut [])
    }
}

// SAFETY: PooledBuf only holds a Vec and Arc; both are Send.
unsafe impl Send for PooledBuf {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_reuses_buffers() {
        let pool = BufPool::with_capacity(64, 8);
        {
            let a = pool.copy_from(&[1, 2, 3]);
            assert_eq!(&*a, &[1, 2, 3]);
        }
        assert_eq!(pool.free_len(), 1);
        let b = pool.copy_from(&[9, 9]);
        assert_eq!(&*b, &[9, 9]);
        // Took the recycled slab; free list empty until drop.
        assert_eq!(pool.free_len(), 0);
        drop(b);
        assert_eq!(pool.free_len(), 1);
    }

    #[test]
    fn pool_caps_free_list() {
        let pool = BufPool::with_capacity(32, 2);
        let mut held = Vec::new();
        for i in 0..5 {
            held.push(pool.copy_from(&[i]));
        }
        drop(held);
        assert!(pool.free_len() <= 2);
    }
}
