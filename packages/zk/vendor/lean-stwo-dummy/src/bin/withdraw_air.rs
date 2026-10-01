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

fn arr32(s: &str) -> [u8; 32] {
    let raw = hex_decode(s);
    let mut a = [0u8; 32];
    a[..raw.len().min(32)].copy_from_slice(&raw[..raw.len().min(32)]);
    a
}

fn main() {
    let mut args = env::args().skip(1);
    let cmd = args.next().expect("prove-nw|verify-nw|prove-pw|verify-pw|commit");
    match cmd.as_str() {
        "commit" => {
            let addr = hex_decode(&args.next().unwrap_or_else(|| "00".repeat(20)));
            let secret = hex_decode(&args.next().unwrap_or_else(|| "00".repeat(32)));
            let t = lean_stwo_dummy::withdraw_commit(&addr, &secret);
            io::stdout()
                .write_all(t.iter().map(|b| format!("{b:02x}")).collect::<String>().as_bytes())
                .unwrap();
        }
        "prove-nw" => {
            let period: u64 = args.next().expect("period").parse().unwrap();
            let prev = arr32(&args.next().unwrap_or_else(|| "00".repeat(32)));
            let commit = arr32(&args.next().expect("commit hex"));
            let (acc, proof) = lean_stwo_dummy::prove_no_withdraw(period, &prev, &commit).expect("prove");
            let mut out = Vec::new();
            out.extend_from_slice(&acc);
            out.extend_from_slice(&proof);
            io::stdout().write_all(&out).unwrap();
        }
        "verify-nw" => {
            let period: u64 = args.next().expect("period").parse().unwrap();
            let acc = arr32(&args.next().expect("acc hex"));
            let prev = arr32(&args.next().unwrap_or_else(|| "00".repeat(32)));
            let mut proof = Vec::new();
            io::stdin().read_to_end(&mut proof).unwrap();
            lean_stwo_dummy::verify_no_withdraw(&proof, period, &acc, &prev).expect("verify");
        }
        "prove-pw" => {
            let period: u64 = args.next().expect("period").parse().unwrap();
            let old = arr32(&args.next().expect("old commit"));
            let amount: u64 = args.next().expect("amount").parse().unwrap();
            let (next, proof) = lean_stwo_dummy::prove_partial_withdraw(period, &old, amount).expect("prove");
            let mut out = Vec::new();
            out.extend_from_slice(&next);
            out.extend_from_slice(&proof);
            io::stdout().write_all(&out).unwrap();
        }
        "verify-pw" => {
            let period: u64 = args.next().expect("period").parse().unwrap();
            let old = arr32(&args.next().expect("old"));
            let newc = arr32(&args.next().expect("new"));
            let mut proof = Vec::new();
            io::stdin().read_to_end(&mut proof).unwrap();
            lean_stwo_dummy::verify_partial_withdraw(&proof, period, &old, &newc).expect("verify");
        }
        other => panic!("unknown {other}"),
    }
}
