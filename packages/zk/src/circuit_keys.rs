// //! Unified circuit key management for zk circuits.
// //!
// //! Provides a trait [`ZkCircuitKeys`] that each circuit implements to:
// //! - Build proving and verifying keys from a halo2 circuit
// //! - Write keys to a CosmWasm-style `./artifacts/` directory with `{circuit_name}_*.bin` names
// //! - Read keys back from the same artifacts directory
// //! - Generate [`CircuitFooter`](crate::CircuitFooter) metadata for on-chain VM verification
// //!
// //! ## Artifacts layout
// //!
// //! ```text
// //! artifacts/
// //!   headstash_params.bin    # SRS params (K=18 for headstash)
// //!   headstash_vk.bin         # Verifying key
// //!   headstash_pk.bin         # Proving key
// //!   headstash_footer.bin     # CircuitFooter (optional)
// //! ```
// //!
// //! ## Usage
// //!
// //! ```ignore
// //! use zk_cosmwasm::circuit_keys::ZkCircuitKeys;
// //!
// //! // One-shot: build and write all keys
// //! let paths = HeadstashCircuit::write_keys("./artifacts").unwrap();
// //!
// //! // Read back
// //! let (params, vk, pk) = HeadstashCircuit::read_keys("./artifacts").unwrap();
// //! ```

// use std::fs;
// use std::io::{self, BufReader, BufWriter, Read, Write};
// use std::path::{Path, PathBuf};

// use crate::CircuitFooter;

// use halo2_proofs::plonk;
// use halo2_proofs::poly::commitment::Params;
// use pasta_curves::{pallas, vesta};

// /// Unified key I/O trait for halo2-based zk circuits.
// ///
// /// Each distinct circuit type implements this trait by specifying its
// /// `Circuit` type, `CIRCUIT_NAME`, and `K` value. Default method impls
// /// handle building, writing, and reading keys — so concrete circuits
// /// only need a few lines.
// ///
// /// The naming convention (`{circuit_name}_*.bin`) mirrors CosmWasm's
// /// `{contract_name}.wasm` pattern, making it easy to identify which
// /// artifacts belong to which circuit in a shared `./artifacts/` directory.
// pub trait ZkCircuitKeys {
//     /// The concrete halo2 plonk circuit type (must be `Default`-constructible
//     /// for key generation without witnesses).
//     type Circuit: plonk::Circuit<pallas::Base> + Default;

//     /// Circuit name used as the filename prefix, e.g. `"headstash"`, `"norick"`.
//     const CIRCUIT_NAME: &'static str;

//     /// `K` value — base-2 log of the circuit's domain size.
//     const K: u32;

//     // ── Build helpers ─────────────────────────────────────────────────

//     /// Build SRS params for this circuit's `K`.
//     fn build_params() -> Params<vesta::Affine> {
//         Params::new(Self::K)
//     }

//     /// Build proving key from scratch via params + keygen.
//     fn build_proving_key() -> (Params<vesta::Affine>, plonk::ProvingKey<vesta::Affine>) {
//         let params = Self::build_params();
//         let circuit: Self::Circuit = Default::default();
//         let vk = plonk::keygen_vk(&params, &circuit).unwrap();
//         let pk = plonk::keygen_pk(&params, vk, &circuit).unwrap();
//         (params, pk)
//     }

//     /// Build verifying key only (cheaper than full proving key).
//     fn build_verifying_key() -> (Params<vesta::Affine>, plonk::VerifyingKey<vesta::Affine>) {
//         let params = Self::build_params();
//         let circuit: Self::Circuit = Default::default();
//         let vk = plonk::keygen_vk(&params, &circuit).unwrap();
//         (params, vk)
//     }

//     /// Generate a [`CircuitFooter`] encoding constraint-system metadata.
//     ///
//     /// The footer is embedded in WASM binaries so the on-chain VM can
//     /// deserialize and verify proofs without the original Rust circuit type.
//     fn generate_footer() -> CircuitFooter {
//         use halo2_proofs::plonk::Circuit as Halo2Circuit;

//         let params = Self::build_params();
//         let vk = Self::build_verifying_key();

//         let mut cs = plonk::ConstraintSystem::<pallas::Base>::default();
//         let _ = <Self::Circuit as Halo2Circuit<pallas::Base>>::configure(&mut cs);

//         let mut params_buf = Vec::new();
//         vk.0.write(&mut params_buf).expect("params serialization");
//         let mut vk_buf = Vec::new();
//         vk.1.write(&mut vk_buf).expect("vk serialization");
//         let mut cs_buf = Vec::new();
//         cs.write(&mut cs_buf).expect("cs serialization");

//         let num_gates = if cs_buf.len() >= 12 {
//             u16::from_le_bytes([cs_buf[10], cs_buf[11]]) as u32
//         } else {
//             0
//         };

//         CircuitFooter::new(
//             crate::CircuitType::Plonkish,
//             cs.get_num_instance_columns() as u8,
//             cs.get_num_fixed_columns(),
//             cs.get_num_advice(),
//             cs.get_num_instance_columns(),
//             cs.degree() as u8,
//             params_buf.len() as u32,
//             vk_buf.len() as u32,
//             cs_buf.len() as u32,
//             cs.get_num_selectors(),
//             num_gates,
//             true, // has_lookups
//             0,    // crc32 placeholder
//         )
//     }

//     // ── File path helpers ─────────────────────────────────────────────

//     /// Path to the `{circuit_name}_params.bin` file.
//     fn params_path(artifact_dir: &Path) -> PathBuf {
//         artifact_dir.join(format!("{}_params.bin", Self::CIRCUIT_NAME))
//     }

//     /// Path to the `{circuit_name}_vk.bin` file.
//     fn vk_path(artifact_dir: &Path) -> PathBuf {
//         artifact_dir.join(format!("{}_vk.bin", Self::CIRCUIT_NAME))
//     }

//     /// Path to the `{circuit_name}_pk.bin` file.
//     fn pk_path(artifact_dir: &Path) -> PathBuf {
//         artifact_dir.join(format!("{}_pk.bin", Self::CIRCUIT_NAME))
//     }

//     /// Path to the `{circuit_name}_footer.bin` file.
//     fn footer_path(artifact_dir: &Path) -> PathBuf {
//         artifact_dir.join(format!("{}_footer.bin", Self::CIRCUIT_NAME))
//     }

//     /// All four artifact file paths.
//     fn all_paths(artifact_dir: &Path) -> [PathBuf; 4] {
//         [
//             Self::params_path(artifact_dir),
//             Self::vk_path(artifact_dir),
//             Self::pk_path(artifact_dir),
//             Self::footer_path(artifact_dir),
//         ]
//     }

//     // ── Individual write helpers ──────────────────────────────────────

//     /// Write SRS params to `{circuit_name}_params.bin`.
//     fn write_params_to(artifact_dir: &Path, params: &Params<vesta::Affine>) -> io::Result<PathBuf> {
//         let path = Self::params_path(artifact_dir);
//         fs::create_dir_all(artifact_dir)?;
//         let mut writer = BufWriter::new(fs::File::create(&path)?);
//         params.write(&mut writer)?;
//         writer.flush()?;
//         Ok(path)
//     }

//     /// Write verifying key to `{circuit_name}_vk.bin`.
//     fn write_vk_to(
//         artifact_dir: &Path,
//         vk: &plonk::VerifyingKey<vesta::Affine>,
//     ) -> io::Result<PathBuf> {
//         let path = Self::vk_path(artifact_dir);
//         fs::create_dir_all(artifact_dir)?;
//         let mut writer = BufWriter::new(fs::File::create(&path)?);
//         vk.write(&mut writer)?;
//         writer.flush()?;
//         Ok(path)
//     }

//     /// Write proving key to `{circuit_name}_pk.bin`.
//     fn write_pk_to(
//         artifact_dir: &Path,
//         pk: &plonk::ProvingKey<vesta::Affine>,
//     ) -> io::Result<PathBuf> {
//         let path = Self::pk_path(artifact_dir);
//         fs::create_dir_all(artifact_dir)?;
//         let mut writer = BufWriter::new(fs::File::create(&path)?);
//         pk.get_vk().write(&mut writer)?;
//         writer.flush()?;
//         Ok(path)
//     }

//     /// Write circuit footer bytes to `{circuit_name}_footer.bin`.
//     fn write_footer_to(artifact_dir: &Path, footer: &[u8]) -> io::Result<PathBuf> {
//         let path = Self::footer_path(artifact_dir);
//         fs::create_dir_all(artifact_dir)?;
//         fs::write(&path, footer)?;
//         Ok(path)
//     }

//     // ── Batch build + write ───────────────────────────────────────────

//     /// Build all keys and write them to the artifacts directory.
//     ///
//     /// Returns `[params_path, vk_path, pk_path, footer_path]`.
//     fn write_keys(artifact_dir: &Path) -> io::Result<[PathBuf; 4]> {
//         let (params, pk) = Self::build_proving_key();
//         let params_path = Self::write_params_to(artifact_dir, &params)?;
//         let vk_path = Self::write_vk_to(artifact_dir, pk.get_vk())?;
//         let pk_path = Self::write_pk_to(artifact_dir, &pk)?;
//         let footer = Self::generate_footer();
//         let footer_path = Self::write_footer_to(artifact_dir, &footer.to_bytes())?;
//         Ok([params_path, vk_path, pk_path, footer_path])
//     }

//     // ── Individual read helpers ───────────────────────────────────────

//     /// Read SRS params from `{circuit_name}_params.bin`.
//     fn read_params_from(artifact_dir: &Path) -> io::Result<Params<vesta::Affine>> {
//         let path = Self::params_path(artifact_dir);
//         let mut reader = BufReader::new(fs::File::open(&path)?);
//         Params::read(&mut reader)
//     }

//     /// Read verifying key from `{circuit_name}_vk.bin`.
//     fn read_vk_from(artifact_dir: &Path) -> io::Result<plonk::VerifyingKey<vesta::Affine>> {
//         let path = Self::vk_path(artifact_dir);
//         let mut reader = BufReader::new(fs::File::open(&path)?);
//         plonk::VerifyingKey::read(&mut reader, &Params::new(Self::K))
//     }

//     /// Read proving key from `{circuit_name}_pk.bin`.
//     fn read_pk_from(artifact_dir: &Path) -> io::Result<plonk::ProvingKey<vesta::Affine>> {
//         let path = Self::pk_path(artifact_dir);
//         let mut reader = BufReader::new(fs::File::open(&path)?);
//         plonk::ProvingKey::re(&mut reader, Params::new(Self::K))
//     }

//     // ── Batch read ────────────────────────────────────────────────────

//     /// Read all keys from the artifacts directory.
//     fn read_keys(
//         artifact_dir: &Path,
//     ) -> io::Result<(
//         Params<vesta::Affine>,
//         plonk::VerifyingKey<vesta::Affine>,
//         plonk::ProvingKey<vesta::Affine>,
//     )> {
//         let params = Self::read_params_from(artifact_dir)?;
//         let vk = Self::read_vk_from(artifact_dir)?;
//         let pk = Self::read_pk_from(artifact_dir)?;
//         Ok((params, vk, pk))
//     }
// }

// // ── Blanket impl for any Circuit implementor ──────────────────────────
// //
// // Any type that is already plonk::Circuit<pallas::Base> + Default can
// // implement ZkCircuitKeys by specifying its name and K:
// //
// //   impl ZkCircuitKeys for MyCircuit {
// //       type Circuit = MyCircuit;
// //       const CIRCUIT_NAME: &'static str = "my-circuit";
// //       const K: u32 = 16;
// //   }
