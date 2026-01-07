//! main suite for headstash

use halo2_proofs::{plonk, COSMWASM_METADATA_LENGTH};
use rand_core::OsRng;

// use alloc::boxed::Box;
// use rayon::prelude::*;
// use rayon::slice::ParallelSlice;
// use base64::{engine::general_purpose, Engine as _};
// use zk_headstash::address::RecpAddr;
// use zk_headstash::builder::SpendInfo;
// use zk_headstash::circuit::{Circuit, Instance, ProvingKey, VerifyingKey};
// use zk_headstash::keys::{EligibleSk, FullViewingKey, NullifierDerivingKey, SpendingKey};
// use zk_headstash::note::{ExtractedNoteCommitment, Note, RandomSeed, Rho};
// use zk_headstash::tree::MerklePath;
// use zk_headstash::value::{TestPressValue, NoteDenom, NoteValue};
// use zk_headstash::{spec, Anchor, Proof};
// use secp256k1::SecretKey;
// use sinsemilla::HashDomain;

use pasta_curves::{vesta, Fp};

use std::error::Error;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::string::String;

use std::vec::Vec;
use std::{env, eprintln, fs, println};

const KEYS_DIR: &str = "./circuit_keys";
const PARAMS_FILE: &str = "params.bin";
const VK_FILE: &str = "verifying_key.bin";
const PK_FILE: &str = "proving_key.bin";

/// BoxError
pub type BoxError = Box<dyn Error + Send + Sync>;
/// get_cli_args
pub fn get_cli_args() -> Result<(String, String), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("flag format: {} <input-file> <address>", args[0]);
        std::process::exit(1);
    }
    Ok((args[1].clone(), args[2].clone()))
}

/// // unit test
// integation test
// prop test
// verify current deployments
// suite
/// TerpTestPressConfig
#[derive(Debug)]
pub struct TerpTestPressConfig {
    // smart contract params
    // file location params
    // storage params
    // deployment params
    // node params
    // app
    // wallet gen
    // headstash gen
    // cw-headstash cw-orch suite
}

/// TestPressSuite
#[derive(Debug, Default)]
pub struct TestPressSuite {}
impl TestPressBitwiseInstance for TestPressSuite {}
impl TestPressLaunchpadInstance for TestPressSuite {}
impl TestPressSuite {
    /// create new headsatsh suite
    pub fn new() -> Self {
        Self {}
    }
}

/// TestPressBitwiseInstance
pub trait TestPressBitwiseInstance {}

/// launchpad
pub trait TestPressLaunchpadInstance: TestPressBitwiseInstance {
    /// `gen_test_circuit_keys`: generate or load test circuit keys and create multiple proofs for NoRickCircuit
    /// - `generate_keys`: if true, generates new keys per spec of zk-wasmvm vk serialization, and writes to `path`; if false, loads keys from `key_path`
    /// - `key_path`: path to load keys from if `generate_keys` is false
    /// - `proof_specs`: vector of (private_word, forbidden_word) pairs to generate proofs for
    /// Returns a vector of proofs
    fn gen_test_circuit_keys(
        &self,
        path: &Path,
        key_path: Option<&Path>,
        proof_specs: Vec<(&str, &str)>,
    ) -> Result<Vec<crate::example_circuits::NoRickProof>, BoxError> {
        use crate::example_circuits::{
            NoRickCircuit, NoRickInstance, NoRickProof, NoRickProvingKey,
        };

        let mut rng = OsRng;
        let mut proofs = Vec::new();

        let pk = if let Some(kp) = key_path {
            eprintln!("🔑 Loading test circuit keys from {}...", kp.display());
            // TODO: Load compressed params/vk file
            // Load params and vk separately
            let params_path = kp.join("params.bin");
            let circuit_path = kp.join("verifying_key.bin");
            let params = halo2_proofs::poly::commitment::Params::<vesta::Affine>::read(
                &mut std::fs::File::open(params_path)?,
            )?;
            let vk = plonk::VerifyingKey::<vesta::Affine>::read::<
                File,
                NoRickCircuit<pasta_curves::Fp>,
            >(&mut std::fs::File::open(circuit_path)?, &params)?;
            let circuit: NoRickCircuit<pasta_curves::Fp> = Default::default();
            let pk = plonk::keygen_pk(&params, vk, &circuit)?;
            let nrpk = NoRickProvingKey::new(pk, params);
            println!("NoRickProvingKey: {:#?}", nrpk);
            nrpk
        } else {
            eprintln!("🔑 Generating test circuit keys for example circuits...");
            fs::create_dir_all(path)?;
            // IMPORTANT: Use the SAME params/pk that are written to file!
            // Previously called NoRickProvingKey::build() which created NEW random params,
            // causing params mismatch between proof creation and verification.
            let nrpk = self.gen_no_rick_circuit_keys(path)?;
            eprintln!("✅ All test circuit keys generated successfully");
            nrpk
        };

        for (private_word, forbidden_word) in proof_specs {
            let mut bytes = private_word.as_bytes().to_vec();
            bytes.resize(20, 0);
            println!(
                "resized {} byte string to full 20 via padding",
                private_word.len()
            );

            let priv_input: Vec<halo2_proofs::circuit::Value<Fp>> = bytes
                .iter()
                .map(|&b| halo2_proofs::circuit::Value::known(Fp::from(b as u64)))
                .collect();
            let circuit: NoRickCircuit<pasta_curves::Fp> = NoRickCircuit { priv_input };
            let instance = NoRickInstance {
                word: forbidden_word.into(),
            };
            let proof: NoRickProof = NoRickProof::create(&pk, &[circuit], &[instance], &mut rng)?;
            proofs.push(proof);
        }

        Ok(proofs)
    }

    /// Generate keys for NoRickCircuit example.
    /// Follows specification of zk-wasmvm
    #[cfg(feature = "zk-tests")]
    fn gen_no_rick_circuit_keys(
        &self,
        base_path: &Path,
    ) -> Result<crate::example_circuits::NoRickProvingKey, BoxError> {
        use crate::example_circuits::NoRickCircuit;
        use halo2_proofs::plonk::Circuit;
        use std::io::{self, Seek};
        eprintln!("  📝 Generating NoRickCircuit keys...");
        const I: u8 = 1;
        const V: CircuitType = CircuitType::Plonkish;
        const K: u32 = 10;
        let cd = base_path.join("no_rick");
        fs::create_dir_all(&cd)?;

        let mut cs = plonk::ConstraintSystem::<Fp>::default();
        let circuit: NoRickCircuit<Fp> = NoRickCircuit::default();
        NoRickCircuit::<Fp>::configure(&mut cs);
        println!("cs.pinned: {:#?}", cs.pinned());

        let p = halo2_proofs::poly::commitment::Params::<vesta::Affine>::new(K);
        let vk = plonk::keygen_vk(&p, &circuit).map_err(|e| format!("VK: {:?}", e))?;
        let pk = plonk::keygen_pk(&p, vk.clone(), &circuit).map_err(|e| format!("PK: {:?}", e))?;
        let pp = cd.join("params.bin");
        let vp = cd.join("verifying_key.bin");
        let cp = cd.join("vk_combined.bin");

        // params w/ V and I as the first two bytes
        let mut pf = BufWriter::new(File::create(&pp)?);
        p.write(&mut pf)?;
        pf.flush()?;
        eprintln!("✓ Params written to {}", pp.display());

        // verifying key
        let mut vf = BufWriter::new(File::create(&vp)?);
        vk.write(&mut vf)?;
        vf.flush()?;
        eprintln!("✓ Verifying key written to {}", vp.display());

        // After writing vk to vp
        let vk_data = fs::read(&vp)?;
        eprintln!("✓ Standalone VK size: {} bytes", vk_data.len());
        eprintln!("  First byte (should be 0x01): 0x{:02x}", vk_data[0]);
        eprintln!(
            "First 20 bytes: {:02x?}",
            &vk_data[0..20.min(vk_data.len())]
        );

        // vk-params||vk
        let mut combined_file = BufWriter::new(File::create(&cp)?);

        // Track position before writing params
        let mut temp = Vec::new();
        p.write(&mut temp)?;
        let params_len = temp.len() as u32;
        eprintln!("norick: ✓ Params size: {} bytes", params_len);
        combined_file.write_all(&temp)?;

        // Track position before writing vk
        let mut temp = Vec::new();
        vk.write(&mut temp)?;
        let vk_len = temp.len() as u32;
        eprintln!("norick: ✓ Verifying key size: {} bytes", vk_len);
        combined_file.write_all(&temp)?;

        // VERSION 2: Serialize constraint system for circuit-agnostic verification
        eprintln!("norick: 📝 Serializing constraint system (v2 format)...");
        let mut cs_temp = Vec::new();
        cs.write(&mut cs_temp)?;
        let cs_len = cs_temp.len() as u32;
        eprintln!("norick: ✓ Constraint system size: {} bytes", cs_len);
        combined_file.write_all(&cs_temp)?;

        // WRITE EXTENDED 32-BYTE METADATA FOOTER using CircuitFooter v2
        use crate::cosmwasm_circuit::{CircuitFooter, CircuitType};

        // Get column counts from CS
        let num_fixed = cs.get_num_fixed_columns();
        let num_advice = cs.get_num_advice();
        let num_instance = cs.get_num_instance_columns();
        let num_selectors = cs.get_num_selectors();
        let num_gates = cs.get_gate_count() as u32;
        let has_lookups = false; // NoRickCircuit has no lookups

        eprintln!("norick: CS summary:");
        eprintln!("  fixed_columns: {}", num_fixed);
        eprintln!("  advice_columns: {}", num_advice);
        eprintln!("  instance_columns: {}", num_instance);
        eprintln!("  selectors: {}", num_selectors);
        eprintln!("  gates: {}", num_gates);
        eprintln!("  degree: {}", cs.degree());

        let footer = CircuitFooter::new_v2(
            V,
            I,
            num_fixed,
            num_advice,
            num_instance,
            cs.degree() as u8,
            params_len,
            vk_len,
            cs_len,
            num_selectors,
            num_gates,
            has_lookups,
            0, // crc32 (not computed for now)
        );

        let metadata_start = combined_file.seek(io::SeekFrom::Current(0))?;
        combined_file.write_all(&footer.to_bytes())?;
        let metadata_end = combined_file.seek(io::SeekFrom::Current(0))?;
        let actual_metadata_len = (metadata_end - metadata_start) as usize;

        assert_eq!(
            actual_metadata_len, COSMWASM_METADATA_LENGTH,
            "norick: Metadata size mismatch: wrote {} bytes, expected {}",
            actual_metadata_len, COSMWASM_METADATA_LENGTH
        );
        eprintln!(
            "norick: CircuitFooter v2 written: {} bytes",
            actual_metadata_len
        );
        eprintln!(
            "norick: instance_count={}, fixed={}, advice={}, instance={}, degree={}",
            I, num_fixed, num_advice, num_instance, cs.degree()
        );
        eprintln!("  params_len: {}, vk_len: {}, cs_len: {}", params_len, vk_len, cs_len);

        combined_file.flush()?;
        eprintln!(
            "✅ Total combined file written: {} bytes (v2 format: params+vk+cs+footer)",
            combined_file.seek(io::SeekFrom::End(0))?
        );

        // Debug: read back what we just wrote
        let written_data = fs::read(&cp)?;
        eprintln!(
            "norick: Combined file total size: {} bytes",
            written_data.len()
        );
        eprintln!(
            "norick: Params section (first 20 bytes): {:02x?}",
            &written_data[0..20]
        );
        let vk_start = params_len as usize;
        eprintln!(
            "norick: VK section (bytes {}-{}): {:02x?}",
            vk_start,
            (vk_start + 20).min(written_data.len()),
            &written_data[vk_start..(vk_start + 20).min(written_data.len())]
        );
        let cs_start = (params_len + vk_len) as usize;
        eprintln!(
            "norick: CS section (bytes {}-{}): {:02x?}",
            cs_start,
            (cs_start + 20).min(written_data.len()),
            &written_data[cs_start..(cs_start + 20).min(written_data.len())]
        );
        eprintln!(
            "norick: Footer (last 32 bytes): {:02x?}",
            &written_data[written_data.len() - 32..]
        );

        // proving key
        let pkp = cd.join("proving_key.bin");
        let mut pkf = BufWriter::new(File::create(&pkp)?);
        pk.get_vk().write(&mut pkf)?;
        pkf.flush()?;
        eprintln!("norick: Proving key written to {}", pkp.display());

        // Return the ProvingKey so proofs use the SAME params as written to file
        Ok(crate::example_circuits::NoRickProvingKey::new(pk, p))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde_json::{json, Value};
    use std::boxed::Box;
    use std::collections::{BTreeMap, HashMap};

    #[test]
    pub fn test_cs_serialization_deserialization() -> Result<(), BoxError> {

        Ok(())
    }

    // cargo test --package zk-cosmwasm --features interface test_proof_verification -- --nocapture
    #[test]
    pub fn test_proof_verification() -> Result<(), BoxError> {
        use crate::example_circuits::{NoRickInstance, NoRickProof, NoRickVerifyingKey};

        // Create temp directory for test files
        let temp_dir = Path::new("./test_temp_proofs");
        fs::create_dir_all(temp_dir)?;

        let suite = TestPressSuite::new();

        // Generate circuit keys and proofs
        let proofs = suite.gen_test_circuit_keys(temp_dir, None, vec![("randy", "rick")])?;

        // Load verifying key from file
        let vk_path = temp_dir.join("no_rick").join("verifying_key.bin");
        let params_path = temp_dir.join("no_rick").join("params.bin");

        let mut params_file = fs::File::open(params_path)?;
        let params =
            halo2_proofs::poly::commitment::Params::<vesta::Affine>::read(&mut params_file)?;

        let mut vk_file = fs::File::open(vk_path)?;
        let vk = plonk::VerifyingKey::<vesta::Affine>::read::<
            File,
            crate::example_circuits::NoRickCircuit<pasta_curves::Fp>,
        >(&mut vk_file, &params)?;

        let verifying_key = NoRickVerifyingKey { params, vk };

        // Build proof map
        let mut proof_by_word: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        proof_by_word.insert("rick".to_string(), proofs[0].bytes().clone());

        // Words to include in JSON
        let words = vec!["rick"];

        // Create JSON output
        let mut output = serde_json::Map::new();
        for word in words.clone() {
            let proof_b64 = proof_by_word
                .get(word)
                .map(|bytes| STANDARD.encode(bytes))
                .unwrap_or_else(|| format!("ADD_{}_PROOF_HERE", word.to_uppercase()));

            // Instance scalar: 32 bytes (matching terp-core script)
            let scalar_bytes = [0u8; 32];
            let scalar_b64 = STANDARD.encode(scalar_bytes);

            output.insert(
                word.to_string(),
                json!({
                    "proof": proof_b64,
                    "scalar": scalar_b64
                }),
            );
        }

        let json_output = serde_json::to_string_pretty(&Value::Object(output))?;
        let json_file = temp_dir.join("proofs.json");
        fs::write(&json_file, json_output)?;

        // Now read back and verify
        let json_content = fs::read_to_string(&json_file)?;
        let parsed: Value = serde_json::from_str(&json_content)?;

        for word in words.clone() {
            let word_data = parsed.get(word).unwrap().as_object().unwrap();
            let proof_b64 = word_data.get("proof").unwrap().as_str().unwrap();
            let scalar_b64 = word_data.get("scalar").unwrap().as_str().unwrap();

            // Decode base64
            let proof_bytes = STANDARD.decode(proof_b64)?;

            // Create proof and instance
            let proof = NoRickProof::new(proof_bytes);
            let instance = NoRickInstance {
                word: word.to_string(),
            };

            // Verify proof
            proof.verify(&verifying_key, &[instance])?;
            println!("proof verified ::)");
        }

        // Test with bad proof
        let bad_proof_bytes = vec![0u8; 1024]; // Invalid proof data
        let bad_proof = NoRickProof::new(bad_proof_bytes);
        let bad_instance = NoRickInstance {
            word: "rick".to_string(),
        };
        assert!(
            bad_proof.verify(&verifying_key, &[bad_instance]).is_err(),
            "Invalid proof should fail verification"
        );
        println!("bad proof correctly failed verification ::)");

        // Clean up
        fs::remove_dir_all(temp_dir)?;
        Ok(())
    }
}
