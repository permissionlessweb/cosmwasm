use std::env;
use std::io::{self, Read, Write};

fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn main() {
    let mut args = env::args().skip(1);
    let cmd = args.next().expect("prove|verify|ticket");
    match cmd.as_str() {
        "prove" => {
            let period: u64 = args.next().expect("period").parse().unwrap();
            let height: i64 = args.next().expect("height").parse().unwrap();
            let proposer = hex_decode(&args.next().unwrap_or_else(|| "00".repeat(32)));
            let (ticket, proof) =
                lean_stwo_dummy::prove_ssle(period, height, &proposer).expect("prove");
            // stdout: 32-byte ticket || proof
            let mut out = Vec::new();
            out.extend_from_slice(&ticket);
            out.extend_from_slice(&proof);
            io::stdout().write_all(&out).unwrap();
        }
        "verify" => {
            let period: u64 = args.next().expect("period").parse().unwrap();
            let height: i64 = args.next().expect("height").parse().unwrap();
            let ticket_hex = args.next().expect("ticket hex");
            let mut ticket = [0u8; 32];
            let raw = hex_decode(&ticket_hex);
            ticket[..raw.len().min(32)].copy_from_slice(&raw[..raw.len().min(32)]);
            let mut proof = Vec::new();
            io::stdin().read_to_end(&mut proof).unwrap();
            lean_stwo_dummy::verify_ssle(&proof, period, height, &ticket).expect("verify");
        }
        "ticket" => {
            let period: u64 = args.next().expect("period").parse().unwrap();
            let height: i64 = args.next().expect("height").parse().unwrap();
            let proposer = hex_decode(&args.next().unwrap_or_else(|| "00".repeat(32)));
            let t = lean_stwo_dummy::ssle_ticket(period, height, &proposer);
            io::stdout()
                .write_all(t.iter().map(|b| format!("{b:02x}")).collect::<String>().as_bytes())
                .unwrap();
        }
        other => panic!("unknown {other}"),
    }
}
