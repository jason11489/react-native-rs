use ark_bn254::Bn254;
use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_std::rand::RngCore;
use ark_std::rand::SeedableRng;
use ark_std::test_rng;
use ark_std::UniformRand;
use ark_std::Zero;

use ark_crypto_primitives::Error;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{bn::Bn, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::{fields::fp::FpVar, prelude::AllocVar};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::marker::PhantomData;
use json_writer::JSONObjectWriter;

// mod circuit;
use crate::datatrade::circuit::{generate_test_input, Registerdata};

fn setup() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let test_input = generate_test_input(22).unwrap();

    let (pk, vk) = {
        let c = test_input.clone();

        Groth16::<Bn254>::setup(c, &mut rng).unwrap()
    };
    let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

    // save pk && save pvk
}
