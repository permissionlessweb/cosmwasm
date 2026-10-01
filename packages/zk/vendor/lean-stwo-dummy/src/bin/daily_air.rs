use std::env;
use std::io::{self, Read, Write};

fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    if s.is_empty() {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn main() {
    let mut args = env::args().skip(1);
    let cmd = args.next().expect("prove|verify|key");
    match cmd.as_str() {
        "prove" => {
            let period: u64 = args.next().expect("period").parse().unwrap();
            let identity = hex_decode(&args.next().unwrap_or_else(|| "00".repeat(32)));
            let mut prev = [0u8; 32];
            let raw = hex_decode(&args.next().unwrap_or_else(|| "00".repeat(32)));
            prev[..raw.len().min(32)].copy_from_slice(&raw[..raw.len().min(32)]);
            let (key, proof) = lean_stwo_dummy::prove_daily(period, &identity, &prev).expect("prove");
            let mut out = Vec::new();
            out.extend_from_slice(&key);
            out.extend_from_slice(&proof);
            io::stdout().write_all(&out).unwrap();
        }
        "verify" => {
            let period: u64 = args.next().expect("period").parse().unwrap();
            let mut key = [0u8; 32];
            let raw = hex_decode(&args.next().expect("day_key hex"));
            key[..raw.len().min(32)].copy_from_slice(&raw[..raw.len().min(32)]);
            let mut prev = [0u8; 32];
            let raw = hex_decode(&args.next().unwrap_or_else(|| "00".repeat(32)));
            prev[..raw.len().min(32)].copy_from_slice(&raw[..raw.len().min(32)]);
            let mut proof = Vec::new();
            io::stdin().read_to_end(&mut proof).unwrap();
            lean_stwo_dummy::verify_daily(&proof, period, &key, &prev).expect("verify");
        }
        "key" => {
            let period: u64 = args.next().expect("period").parse().unwrap();
            let identity = hex_decode(&args.next().unwrap_or_else(|| "00".repeat(32)));
            let t = lean_stwo_dummy::daily_key(period, &identity);
            io::stdout()
                .write_all(t.iter().map(|b| format!("{b:02x}")).collect::<String>().as_bytes())
                .unwrap();
        }
        other => panic!("unknown {other}"),
    }
}
