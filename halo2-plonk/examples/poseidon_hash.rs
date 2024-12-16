use halo2_proofs::poly::kzg::commitment::ParamsKZG;

use halo2curves::bn256::{Bn256, Fr};
use halo2curves::ff::{Field, PrimeField};

use halo2_poseidon::poseidon::primitives::{self as poseidon, ConstantLength};

use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::AccumulatorStrategy;
use halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};

use rand_core::OsRng;

use plonk_example::*;

// 2^k-th root of unity
const K: u32 = 8;

const L: usize = 2;

// TODO: find what the constants influence
const WIDTH: usize = 3;
const RATE: usize = 2;

pub fn main() {
    // commit phase
    let rng = OsRng;
    let secret = "475023450948321098";
    let secret = Fr::from_str_vartime(secret).unwrap();
    let nullifier = Fr::random(rng);
    let message = [secret, nullifier];
    let commitment =
        poseidon::Hash::<_, MySpec<WIDTH, RATE>, ConstantLength<L>, WIDTH, RATE>::init()
            .hash(message);
    println!(
        "secet, with nullifier ({:?}) commited to: {:?}",
        nullifier, commitment,
    );

    let params = ParamsKZG::<Bn256>::setup(K, OsRng);
    let circuit = HashCircuit::<MySpec<WIDTH, RATE>, WIDTH, RATE, L>::new(message);
    let vk = keygen_vk::<_, _, _>(&params, &circuit).unwrap();
    let pk = keygen_pk::<_, _, _>(&params, vk.clone(), &circuit).unwrap();
    println!("Keys successfully generated");

    // Proving
    let public_inputs = vec![commitment]; // commitment
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<_, ProverSHPLONK<_>, _, _, Blake2bWrite<_, _, Challenge255<_>>, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&public_inputs.clone()]],
        OsRng,
        &mut transcript,
    )
    .unwrap();
    let proof = transcript.finalize();

    println!("Proof of knowledge created");

    // Verifying
    let strategy = AccumulatorStrategy::new(&params);
    let mut transcript = Blake2bRead::init(&proof[..]);
    verify_proof::<_, VerifierSHPLONK<_>, _, Blake2bRead<_, _, _>, AccumulatorStrategy<_>>(
        &params,
        &vk,
        strategy,
        &[&[&public_inputs]],
        &mut transcript,
    )
    .unwrap();

    println!("Generated proof is correctly verified");
}
