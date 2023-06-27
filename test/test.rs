use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;

use ark_bn254::Bn254;
use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
use ark_crypto_primitives::snark::SNARK;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ec::Group;

use ark_ed_on_bn254::EdwardsConfig;
use ark_ff::Fp;
use ark_ff::PrimeField;
use ark_groth16::Groth16;

use ark_std::rand::RngCore;
use ark_std::rand::SeedableRng;
use ark_std::test_rng;
use ark_std::UniformRand;
use ark_std::Zero;

use azeroth::circuit::AzerothCircuit;
use azeroth::circuit::FieldMTConfig;
use Error;

use gadget::hashes::CRHScheme;
use rust_module::gadget::hashes::mimc7;

use gadget::merkle_tree::MerkleTree;

use gadget::public_encryptions::elgamal;
use gadget::public_encryptions::AsymmetricEncryptionScheme;

use gadget::symmetric_encrytions::symmetric;
use gadget::symmetric_encrytions::SymmetricEncryption;

// type C = ark_bn254::G1Projective;
// type GG = ark_ec::bn::g1::G1Projective<ark_bn254::g1::Config>;
type C = ark_ed_on_bn254::EdwardsProjective;
type GG = ark_ed_on_bn254::constraints::EdwardsVar;

type F = ark_bn254::Fr;
// type F = ark_ed_on_bn254::Fr;
type H = mimc7::MiMC<F>;

type SEEnc = symmetric::SymmetricEncryptionScheme<F>;
type ElGamal = elgamal::ElGamal<C>;
// type HG = mimc7::constraints::MiMCGadget<F>;
// type TwoToOneHG = mimc7::constraints::TwoToOneMiMCGadget<F>;

type FieldMT = MerkleTree<FieldMTConfig<F>>;

#[allow(non_snake_case)]
fn generate_test_input() -> Result<AzerothCircuit<C, GG>, Error> {}

#[test]
fn test_data() {
    println!("{:?}", 1);
}
