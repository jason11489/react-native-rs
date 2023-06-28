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
pub struct Registerdata<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
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
    pub data: Option<Vec<C::BaseField>>,
    pub k_data: Option<C::BaseField>,
    pub ct_r: Option<C::BaseField>,
    pub ct_data: Option<Vec<C::BaseField>>,

    pub _curve_var: PhantomData<GG>,
}

#[allow(non_snake_case)]
impl<C, GG> ConstraintSynthesizer<C::BaseField> for Registerdata<C, GG>
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
        let ct_data_binding: Vec<FpVar<<C as CurveGroup>::BaseField>> = binding
            .iter()
            .map(|i| FpVar::new_witness(ark_relations::ns!(cs, "ct_data{i}"), || Ok(i)).unwrap())
            .collect();

        let hash_input = ct_data_binding;
        let result_h_ct = MiMCGadget::<C::BaseField>::evaluate(&rc, &hash_input).unwrap();

        result_h_ct.enforce_equal(&h_ct).unwrap();

        //==============================================================================================================

        // ct_data = SE.Enc(data,k_data)
        let randomness: symmetric::Randomness<_> = symmetric::Randomness {
            r: self.ct_r.clone().unwrap(),
        };
        let ct_r =
            symmetric::constraints::RandomnessVar::new_witness(ark_relations::ns!(cs, "r"), || {
                Ok(randomness)
            })
            .unwrap();

        let binding = self.ct_data.clone().unwrap();

        let ct_data: Vec<symmetric::constraints::CiphertextVar<C::BaseField>> = binding
            .iter()
            .map(|i| {
                <SymmetricEncryptionSchemeGadget<C::BaseField> as SymmetricEncryptionGadget<
                    SymmetricEncryptionScheme<C::BaseField>,
                    C::BaseField,
                >>::CiphertextVar::new_witness(
                    ark_relations::ns!(cs, "ct_data{i}"),
                    || {
                        Ok(symmetric::Ciphertext {
                            r: self.ct_r.unwrap(),
                            c: *i,
                        })
                    }, // tk_addr_ena_old
                )
                .unwrap()
            })
            .collect();

        let data: Vec<symmetric::constraints::PlaintextVar<C::BaseField>> = self
            .data
            .clone()
            .unwrap()
            .iter()
            .map(|i| {
                <SymmetricEncryptionSchemeGadget<C::BaseField> as SymmetricEncryptionGadget<
                    SymmetricEncryptionScheme<C::BaseField>,
                    C::BaseField,
                >>::PlaintextVar::new_witness(
                    ark_relations::ns!(cs, "data{i}"),
                    || Ok(symmetric::Plaintext { m: *i }), // tk_addr_ena_old
                )
                .unwrap()
            })
            .collect();

        let binding = self.k_data.clone().unwrap();

        let k_data = <SymmetricEncryptionSchemeGadget<C::BaseField> as SymmetricEncryptionGadget<
            SymmetricEncryptionScheme<C::BaseField>,
            C::BaseField,
        >>::SymmetricKeyVar::new_witness(
            ark_relations::ns!(cs, "k_data"),
            || Ok(symmetric::SymmetricKey { k: binding }),
        )
        .unwrap();

        for i in 0..self.data.unwrap().len() {
            let result_ct_data = SymmetricEncryptionSchemeGadget::<C::BaseField>::encrypt(
                rc.clone(),
                ct_r.clone(),
                k_data.clone(),
                data[i].clone(),
            )
            .unwrap();

            result_ct_data.enforce_equal(&ct_data[i]);
        }

        Ok(())

        //==============================================================================================================
    }
}

use crate::gadget::hashes::CRHScheme;
type C = ark_ed_on_bn254::EdwardsProjective;
type GG = ark_ed_on_bn254::constraints::EdwardsVar;

type F = ark_bn254::Fr;
type H = mimc7::MiMC<F>;

type SEEnc = symmetric::SymmetricEncryptionScheme<F>;

#[allow(non_snake_case)]
pub fn generate_test_input() -> Result<Registerdata<C, GG>, Error> {
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

    let mut data: Vec<F> = Vec::new();
    let mut ct_data: Vec<F> = Vec::new();
    for i in 0..45 {
        data.push(F::rand(rng));
    }
    let cin_r = F::rand(rng);
    let random = symmetric::Randomness { r: cin_r.clone() };
    let key = symmetric::SymmetricKey { k: k_data };

    for i in 0..45 {
        ct_data.push(
            SEEnc::encrypt(
                rc.clone(),
                random.clone(),
                key.clone(),
                symmetric::Plaintext { m: data[i] },
            )
            .unwrap()
            .c,
        )
    }

    //==============================================================================================================

    // let data = F::rand(rng);
    // let cin_r = F::rand(rng);
    // let random = symmetric::Randomness { r: cin_r.clone() };
    // let key = symmetric::SymmetricKey { k: k_data };
    // let ct_data = SEEnc::encrypt(
    //     rc.clone(),
    //     random.clone(),
    //     key.clone(),
    //     symmetric::Plaintext { m: data },
    // )
    // .unwrap();

    //==============================================================================================================

    let h_ct = H::evaluate(&rc.clone(), ct_data.clone()).unwrap();

    Ok(Registerdata {
        rc: rc.clone().round_constants,
        h_ct: Some(h_ct),
        h_k_data: Some(h_k_data),
        pk_peer_own: Some(pk_peer_own),
        data: Some(data),
        k_data: Some(k_data),
        ct_r: Some(cin_r),
        ct_data: Some(ct_data),
        _curve_var: std::marker::PhantomData,
    })
}

// #[test]
pub fn test_Data() -> bool {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    // println!("\nGenerate input!\n");

    let test_input = generate_test_input().unwrap();

    let (pk, vk) = {
        let c = test_input.clone();

        Groth16::<Bn254>::setup(c, &mut rng).unwrap()
    };

    // println!("\nPrepared verifying key!\n");
    let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

    // println!("\nGenerate proof!\n");

    let c = test_input.clone();
    let proof = Groth16::<Bn254>::prove(&pk, c, &mut rng).unwrap();

    // println!("{:?}", proof);

    // let h_k_data_string: String = test_input.h_k_data.unwrap().to_string();
    // let h_k_data: Result<F, _> = F::from_str(&h_k_data_string);

    let mut image: Vec<_> = vec![
        test_input.h_k_data.clone().unwrap(),
        test_input.pk_peer_own.clone().unwrap(),
    ];
    image.append(&mut vec![test_input.h_ct.clone().unwrap()]);

    let tmp = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &image, &proof).unwrap();
    let tmp2 = Groth16::<Bn254>::verify(&vk, &image, &proof).unwrap();
    tmp
}

use std::str::FromStr;

#[test]
fn test_string_to_Fr() {
    let rng = &mut test_rng();

    let fr_value: F = F::rand(rng);

    // Fr 값을 문자열로 저장
    let fr_string: String = fr_value.to_string();
    println!("Fr 값을 문자열로 저장: {}", fr_string);

    // 문자열을 Fr 값으로 변환
    let fr_value_parsed: Result<F, _> = F::from_str(&fr_string);
    match fr_value_parsed {
        Ok(parsed_value) => {
            println!("문자열을 Fr 값으로 변환: {}", parsed_value);
        }
        Err(_) => {
            println!("잘못된 문자열입니다.");
        }
    }
}
