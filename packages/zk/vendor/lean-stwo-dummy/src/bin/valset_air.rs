use std::env;
use std::io::{self, Read, Write};

fn parse_idx(s: &str) -> [u8; 5] {
    let n = u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or_else(|_| s.parse().unwrap());
    let b = n.to_be_bytes();
    [b[3], b[4], b[5], b[6], b[7]]
}

fn main() {
    let mut args = env::args().skip(1);
    let cmd = args.next().expect("prove|verify");
    let period: u64 = args.next().expect("period").parse().unwrap();
    let idx = parse_idx(&args.next().expect("index"));
    let eb: u8 = args.next().expect("eb").parse().unwrap();
    match cmd.as_str() {
        "prove" => {
            let proof = lean_stwo_dummy::prove_valset(period, idx, eb).expect("prove");
            io::stdout().write_all(&proof).unwrap();
        }
        "verify" => {
            let mut proof = Vec::new();
            io::stdin().read_to_end(&mut proof).unwrap();
            lean_stwo_dummy::verify_valset(&proof, period, idx, eb).expect("verify");
        }
        other => panic!("unknown {other}"),
    }
}
