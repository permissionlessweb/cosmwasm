//! Each frame keeps 32 live i64 parameters so Singlepass emits a real Wasm
//! call. The VM call-depth counter counts those activations. The checksum is
//! folded after the recursive call and returned to the contract response so
//! the locals stay live.

/// Number of live i64 scalars per frame.
pub const NUM_LOCALS: usize = 32;

/// Recurse `n` frames deep. Returns `(frame_count, checksum)` where
/// `frame_count == n + 1` (the `n == 0` base frame).
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn deep(
    n: u64,
    s00: u64, s01: u64, s02: u64, s03: u64, s04: u64, s05: u64, s06: u64, s07: u64,
    s08: u64, s09: u64, s10: u64, s11: u64, s12: u64, s13: u64, s14: u64, s15: u64,
    s16: u64, s17: u64, s18: u64, s19: u64, s20: u64, s21: u64, s22: u64, s23: u64,
    s24: u64, s25: u64, s26: u64, s27: u64, s28: u64, s29: u64, s30: u64, s31: u64,
) -> (u64, u64) {
    if n == 0 {
        let base = s00 ^ s01 ^ s02 ^ s03 ^ s04 ^ s05 ^ s06 ^ s07
            ^ s08 ^ s09 ^ s10 ^ s11 ^ s12 ^ s13 ^ s14 ^ s15
            ^ s16 ^ s17 ^ s18 ^ s19 ^ s20 ^ s21 ^ s22 ^ s23
            ^ s24 ^ s25 ^ s26 ^ s27 ^ s28 ^ s29 ^ s30 ^ s31;
        return (1, base);
    }
    let (count, child) = deep(
        n - 1,
        s00.rotate_left(1) ^ n, s01.rotate_left(2) ^ n, s02.rotate_left(3) ^ n, s03.rotate_left(4) ^ n,
        s04.rotate_left(5) ^ n, s05.rotate_left(6) ^ n, s06.rotate_left(7) ^ n, s07.rotate_left(8) ^ n,
        s08.rotate_left(9) ^ n, s09.rotate_left(10) ^ n, s10.rotate_left(11) ^ n, s11.rotate_left(12) ^ n,
        s12.rotate_left(13) ^ n, s13.rotate_left(14) ^ n, s14.rotate_left(15) ^ n, s15.rotate_left(16) ^ n,
        s16.rotate_left(17) ^ n, s17.rotate_left(18) ^ n, s18.rotate_left(19) ^ n, s19.rotate_left(20) ^ n,
        s20.rotate_left(21) ^ n, s21.rotate_left(22) ^ n, s22.rotate_left(23) ^ n, s23.rotate_left(24) ^ n,
        s24.rotate_left(25) ^ n, s25.rotate_left(26) ^ n, s26.rotate_left(27) ^ n, s27.rotate_left(28) ^ n,
        s28.rotate_left(29) ^ n, s29.rotate_left(30) ^ n, s30.rotate_left(31) ^ n, s31.rotate_left(32) ^ n,
    );
    let mix = child
        ^ s00.wrapping_add(s01).wrapping_add(s02).wrapping_add(s03)
        ^ s04.wrapping_add(s05).wrapping_add(s06).wrapping_add(s07)
        ^ s08.wrapping_add(s09).wrapping_add(s10).wrapping_add(s11)
        ^ s12.wrapping_add(s13).wrapping_add(s14).wrapping_add(s15)
        ^ s16.wrapping_add(s17).wrapping_add(s18).wrapping_add(s19)
        ^ s20.wrapping_add(s21).wrapping_add(s22).wrapping_add(s23)
        ^ s24.wrapping_add(s25).wrapping_add(s26).wrapping_add(s27)
        ^ s28.wrapping_add(s29).wrapping_add(s30).wrapping_add(s31);
    (count.wrapping_add(1), mix)
}

/// Recurse `n` deep. `executed_frames == n + 1`.
pub fn recurse(n: u64) -> (u64, u64) {
    deep(
        n,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x0101, 0x1111, 0x2121, 0x3131, 0x4141, 0x5151, 0x6161, 0x7171,
        0x8181, 0x9191, 0xA1A1, 0xB1B1, 0xC1C1, 0xD1D1, 0xE1E1, 0xF1F1,
    )
}
