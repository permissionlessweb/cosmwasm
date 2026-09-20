use std::env;
use std::io::{self, Read, Write};

fn parse_root(s: &str) -> [u8; 32] {
    let s = s.trim_start_matches("0x");
    let raw = hex_decode(s);
    let mut out = [0u8; 32];
    let n = raw.len().min(32);
    out[..n].copy_from_slice(&raw[..n]);
    out
}

fn hex_decode(s: &str) -> Vec<u8> {
    if s.len() % 2 != 0 {
        panic!("hex");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let mut args = env::args().skip(1);
    let cmd = args.next().expect("prove|verify|reject-dummy");
    match cmd.as_str() {
        "prove" => {
            let bf = parse_root(&args.next().expect("bitfield_root hex"));
            let dep = parse_root(&args.next().unwrap_or_else(|| "00".repeat(32)));
            let eb = parse_root(&args.next().unwrap_or_else(|| "00".repeat(32)));
            let proof = lean_stwo_dummy::prove_fold(bf, dep, eb).expect("prove");
            io::stdout().write_all(&proof).unwrap();
        }
        "verify" => {
            let bf = parse_root(&args.next().expect("bitfield_root hex"));
            let dep = parse_root(&args.next().unwrap_or_else(|| "00".repeat(32)));
            let eb = parse_root(&args.next().unwrap_or_else(|| "00".repeat(32)));
            let mut proof = Vec::new();
            io::stdin().read_to_end(&mut proof).unwrap();
            lean_stwo_dummy::verify_fold(&proof, bf, dep, eb).expect("verify");
        }
        "reject-dummy" => {
            let mut blob = Vec::new();
            io::stdin().read_to_end(&mut blob).unwrap();
            lean_stwo_dummy::reject_dummy_n(&blob).expect("should not succeed");
        }
        "hex-roots" => {
            // helper: echo 96-byte hex of three roots
            let bf = parse_root(&args.next().unwrap_or_default());
            let dep = parse_root(&args.next().unwrap_or_default());
            let eb = parse_root(&args.next().unwrap_or_default());
            let mut all = Vec::new();
            all.extend_from_slice(&bf);
            all.extend_from_slice(&dep);
            all.extend_from_slice(&eb);
            println!("{}", hex_encode(&all));
        }
        other => panic!("unknown {other}"),
    }
}
