//! BLAKE2b-256 (native host, deterministic, no personalization).
//!
//! `blake2b_simd` picks AVX2 or SSE4.1 at runtime on x86_64 and uses its
//! portable implementation elsewhere. The digest matches RFC 7693. Guest
//! wasm must not turn on `simd128`. Callers that need a BLAKE2 personal
//! string (ZAP1) cannot pass it through [`blake2b_256`].

/// BLAKE2b with 32-byte output (BLAKE2b-256).
///
/// Pure function of `msg`. No key, salt, or personalization.
pub fn blake2b_256(msg: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new().hash_length(32).hash(msg);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(hash.as_bytes());
    arr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_rfc7693() {
        let a = blake2b_256(b"");
        assert_eq!(a, blake2b_256(b""));
        assert_eq!(
            a,
            hex_literal::hex!("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8")
        );
    }

    #[test]
    fn differs_on_input() {
        assert_ne!(blake2b_256(b"a"), blake2b_256(b"b"));
    }
}
