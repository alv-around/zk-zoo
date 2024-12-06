use std::process;

use ark_bls12_381::Bls12_381;
use ark_bls12_381::Fr;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_poly::univariate::DensePolynomial;
use ark_poly::DenseUVPolynomial;
use ark_poly_commit::kzg10::{Powers, UniversalParams, VerifierKey, KZG10};
use ark_poly_commit::{Error, LabeledPolynomial};
use ark_std::UniformRand;
use rand_core::OsRng;

fn trim<E, P>(
    pp: &UniversalParams<E>,
    mut supported_degree: usize,
) -> Result<(Powers<E>, VerifierKey<E>), Error>
where
    E: Pairing,
    P: DenseUVPolynomial<E::ScalarField>,
{
    if supported_degree == 1 {
        supported_degree += 1;
    }
    let powers_of_g = pp.powers_of_g[..=supported_degree].to_vec();
    let powers_of_gamma_g = (0..=supported_degree)
        .map(|i| pp.powers_of_gamma_g[&i])
        .collect();

    let powers = Powers {
        powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
        powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
    };
    let vk = VerifierKey {
        g: pp.powers_of_g[0],
        gamma_g: pp.powers_of_gamma_g[&0],
        h: pp.h,
        beta_h: pp.beta_h,
        prepared_h: pp.prepared_h.clone(),
        prepared_beta_h: pp.prepared_beta_h.clone(),
    };
    Ok((powers, vk))
}

type UniPoly381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;
type KZG = KZG10<Bls12_381, UniPoly381>;

fn main() {
    // setup phase
    let d = 15;
    let rng = &mut OsRng;
    let pk = KZG::setup(d, true, rng).unwrap();
    let (powers, vk) = trim::<Bls12_381, UniPoly381>(&pk, d).unwrap();
    let challenge = Fr::rand(rng);

    // commit phase
    let f = UniPoly381::rand(d, rng);
    let labeled_f = LabeledPolynomial::new(
        String::from("Super secret poly"),
        f.clone(),
        Some(d),
        Some(2), // we will open a univariate poly at two points
    );

    let (comm_f, randomness) =
        KZG::commit(&powers, &labeled_f, None, None).expect("Commitment failed");
    assert!(!comm_f.0.is_zero(), "Commitment should not be zero");

    // eval phase
    let value = labeled_f.evaluate(&challenge);
    let pi = KZG::open(&powers, &labeled_f, challenge, &randomness).unwrap();

    // verification phase
    match KZG::check(&vk, &comm_f, challenge, value, &pi) {
        Ok(_) => println!("Succesful verification!"),
        Err(_) => {
            eprintln!("failed verification!");
            process::exit(1);
        }
    };
}
