use crate::gadget::{
    hashes::{
        self,
        constraints::CRHSchemeGadget,
        mimc7::{self, constraints::MiMCGadget},
    },
    symmetric_encrytions::{
        constraints::SymmetricEncryptionGadget,
        symmetric::{
            self, constraints::SymmetricEncryptionSchemeGadget, SymmetricEncryptionScheme,
        },
        SymmetricEncryption,
    },
};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};

use ark_bn254::Bn254;
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

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;
#[allow(non_snake_case)]
#[derive(Clone)]
pub struct Tiger<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    // constant
    pub rc: Vec<C::BaseField>, // round_constants

    // public
    pub h_ct: Option<C::BaseField>,
    pub h_k_data: Option<C::BaseField>,
    pub pk_peer_own: Option<C::BaseField>,

    // witness
    pub k_data: Option<C::BaseField>,
    pub ct_data: Option<C::BaseField>,

    pub _curve_var: PhantomData<GG>,
}

#[allow(non_snake_case)]
impl<C, GG> ConstraintSynthesizer<C::BaseField> for Tiger<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<C::BaseField>,
    ) -> ark_relations::r1cs::Result<()> {
        //==============================================================================================================

        let rc = hashes::mimc7::Parameters {
            round_constants: self.rc,
        };
        let rc = hashes::mimc7::constraints::ParametersVar::new_constant(
            ark_relations::ns!(cs, "round constants"),
            &rc.clone(),
        )
        .unwrap();
        //==============================================================================================================
        //h_k_data == Hash(pk_peer_own || k_data)

        let h_k_data = FpVar::new_input(ark_relations::ns!(cs, "h_k_data"), || {
            Ok(self.h_k_data.unwrap())
        })
        .unwrap();

        let pk_peer_own = FpVar::new_input(ark_relations::ns!(cs, "pk_peer_own"), || {
            Ok(self.pk_peer_own.unwrap())
        })
        .unwrap();

        let binding = self.k_data.unwrap();
        let k_data_binding =
            FpVar::new_witness(ark_relations::ns!(cs, "k_data"), || Ok(binding)).unwrap();

        let hash_input = [pk_peer_own, k_data_binding].to_vec();
        let result_h_k_data = MiMCGadget::<C::BaseField>::evaluate(&rc, &hash_input).unwrap();

        result_h_k_data.enforce_equal(&h_k_data).unwrap();

        //==============================================================================================================

        // h_ct == Hash(CT_data)

        let h_ct =
            FpVar::new_input(ark_relations::ns!(cs, "h_ct"), || Ok(self.h_ct.unwrap())).unwrap();

        let binding = self.ct_data.clone().unwrap();
        let ct_data_binding =
            FpVar::new_witness(ark_relations::ns!(cs, "ct_data"), || Ok(binding)).unwrap();

        let hash_input = [ct_data_binding].to_vec();
        let result_h_ct = MiMCGadget::<C::BaseField>::evaluate(&rc, &hash_input).unwrap();

        result_h_ct.enforce_equal(&h_ct)
    }
}

//==============================================================================================================
//==============================================================================================================
//==============================================================================================================
use crate::gadget::hashes::CRHScheme;
type C = ark_ed_on_bn254::EdwardsProjective;
type GG = ark_ed_on_bn254::constraints::EdwardsVar;

type F = ark_bn254::Fr;
type H = mimc7::MiMC<F>;

type SEEnc = symmetric::SymmetricEncryptionScheme<F>;

#[allow(non_snake_case)]
fn generate_test_input() -> Result<Tiger<C, GG>, Error> {
    let rng = &mut test_rng();
    let rc: mimc7::Parameters<F> = mimc7::Parameters {
        round_constants: mimc7::parameters::get_bn256_round_constants(),
    };
    //==============================================================================================================

    let pk_peer_own = F::rand(rng);
    let k_data = F::rand(rng);
    let h_k_data =
        H::evaluate(&rc.clone(), [pk_peer_own.clone(), k_data.clone()].to_vec()).unwrap();
    //==============================================================================================================

    let data = F::rand(rng);
    let cin_r = F::rand(rng);
    let random = symmetric::Randomness { r: cin_r.clone() };
    let key = symmetric::SymmetricKey { k: k_data };
    let ct_data = SEEnc::encrypt(
        rc.clone(),
        random.clone(),
        key.clone(),
        symmetric::Plaintext { m: data },
    )
    .unwrap();

    //==============================================================================================================

    let h_ct = H::evaluate(&rc.clone(), [ct_data.clone().c].to_vec()).unwrap();

    Ok(Tiger {
        rc: rc.clone().round_constants,
        h_ct: Some(h_ct),
        h_k_data: Some(h_k_data),
        pk_peer_own: Some(pk_peer_own),
        k_data: Some(k_data),
        ct_data: Some(ct_data.c),
        _curve_var: std::marker::PhantomData,
    })
}

#[test]
fn test_Data() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    println!("\nGenerate input!\n");

    let test_input = generate_test_input().unwrap();

    let (pk, vk) = {
        let c = test_input.clone();

        Groth16::<Bn254>::setup(c, &mut rng).unwrap()
    };

    // println!("\npk = {:?}\n", vk);

    println!("\nPrepared verifying key!\n");
    let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

    println!("\nGenerate proof!\n");

    let c = test_input.clone();
    let proof = Groth16::<Bn254>::prove(&pk, c, &mut rng).unwrap();

    println!("{:?}", proof);

    let image = &[
        test_input.h_ct.clone().unwrap(),
        test_input.h_k_data.clone().unwrap(),
        test_input.pk_peer_own.clone().unwrap(),
    ];

    let tmp = Groth16::<Bn254>::verify_with_processed_vk(&pvk, image, &proof).unwrap();
    let tmp2 = Groth16::<Bn254>::verify(&vk, image, &proof).unwrap();
    println!("\nresult = {:?}", tmp);
}
