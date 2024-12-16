
use k256::ecdsa::{Signature,VerifyingKey};

use risc0_ecdsa_methods::SIGNATURE_ELF;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

pub fn prove_ecdsa_verification(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Receipt {
    let input = (verifying_key.to_encoded_point(true), message, signature);
    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    prover.prove(env, SIGNATURE_ELF).unwrap()
}
