use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::Result;
use log::{Level, LevelFilter};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::timing::TimingTree;
use plonky2_sha256::circuit::{array_to_bits, make_circuits};
use plonky2_sha256::verifier::{
    generate_circom_verifier, generate_proof_base64, generate_verifier_config,
};
use sha2::{Digest, Sha256};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

pub fn prove_sha256(msg: &[u8]) -> (ProofWithPublicInputs<F, C, D>, CircuitData<F, C, D>) {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let hash = hasher.finalize();
    // println!("Hash: {:#04X}", hash);

    let msg_bits = array_to_bits(msg);
    let len = msg.len() * 8;
    println!("block count: {}", (len + 65 + 511) / 512);

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let targets = make_circuits(&mut builder, len as u64);
    let mut pw = PartialWitness::new();

    for i in 0..len {
        pw.set_bool_target(targets.message[i], msg_bits[i]);
    }

    let expected_res = array_to_bits(hash.as_slice());
    for i in 0..expected_res.len() {
        if expected_res[i] {
            builder.assert_one(targets.digest[i].target);
        } else {
            builder.assert_zero(targets.digest[i].target);
        }
    }

    println!(
        "Constructing inner proof with {} gates",
        builder.num_gates()
    );
    let data = builder.build::<C>();
    let timing = TimingTree::new("prove", Level::Debug);
    let proof = data.prove(pw).unwrap();
    timing.print();

    let timing = TimingTree::new("verify", Level::Debug);
    let _res = data.verify(proof.clone());
    timing.print();

    (proof, data)
}

fn main() -> Result<()> {
    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Debug);
    builder.try_init().unwrap();

    let (proof1, data1) = prove_sha256("Msg 1".as_bytes());
    let (proof2, data2) = prove_sha256("Msg 2".as_bytes());
  println!("here");
    if !Path::new("./circom/test/data").is_dir() {
        std::fs::create_dir("./circom/test/data")?;
    }

  

    let conf = generate_verifier_config(&proof1)?;
    let mut conf_file = File::create("./circom/test/data/conf1.json")?;
    conf_file.write_all(serde_json::to_string(&conf)?.as_ref())?;

    let proof_json = generate_proof_base64(&proof1, &conf)?;
    let mut proof_file = File::create("./circom/test/data/proof1.json")?;
    proof_file.write_all(proof_json.as_bytes())?;

    let conf = generate_verifier_config(&proof2)?;
    let mut conf_file = File::create("./circom/test/data/conf2.json")?;
    conf_file.write_all(serde_json::to_string(&conf)?.as_ref())?;

    let proof_json = generate_proof_base64(&proof1, &conf)?;
    let mut proof_file = File::create("./circom/test/data/proof2.json")?;
    proof_file.write_all(proof_json.as_bytes())?;

    let (circom_constants, circom_gates) =
        generate_circom_verifier(&conf, &data2.common, &data2.verifier_only)?;


    if !Path::new("./circom/circuits").is_dir() {
        std::fs::create_dir("./circom/circuits")?;
    }

    let mut circom_file = File::create("./circom/circuits/constants.circom")?;
    circom_file.write_all(circom_constants.as_bytes())?;
    circom_file = File::create("./circom/circuits/gates.circom")?;
    circom_file.write_all(circom_gates.as_bytes())?;


    Ok(())
}
