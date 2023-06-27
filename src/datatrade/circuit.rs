use crate::gadget::{
    hashes::{
        self,
        constraints::CRHSchemeGadget,
        mimc7::{self, constraints::MiMCGadget},
    },
    merkle_tree::{self, constraints::ConfigGadget, Config, IdentityDigestConverter},
    public_encryptions::{
        elgamal::{self, constraints::ElGamalEncGadget, ElGamal},
        AsymmetricEncryptionGadget,
    },
    symmetric_encrytions::{
        constraints::SymmetricEncryptionGadget,
        symmetric::{
            self, constraints::SymmetricEncryptionSchemeGadget, SymmetricEncryptionScheme,
        },
    },
};

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{AffineRepr, CurveGroup};
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
    pub data: Option<C::BaseField>,
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
        let rc = hashes::mimc7::Parameters {
            round_constants: self.rc,
        };
        let rc = hashes::mimc7::constraints::ParametersVar::new_constant(
            ark_relations::ns!(cs, "round constants"),
            &rc.clone(),
        )
        .unwrap();

        let h_ct =
            FpVar::new_input(ark_relations::ns!(cs, "h_ct"), || Ok(self.h_ct.unwrap())).unwrap();
        let h_k_data = FpVar::new_input(ark_relations::ns!(cs, "h_k_data"), || {
            Ok(self.h_k_data.unwrap())
        })
        .unwrap();
        let pk_peer_own = FpVar::new_input(ark_relations::ns!(cs, "pk_peer_own"), || {
            Ok(self.pk_peer_own.unwrap())
        })
        .unwrap();

        //==============================================================================================================

        let data =
            FpVar::new_witness(ark_relations::ns!(cs, "data"), || Ok(self.data.unwrap())).unwrap();

        let k_data_1 = FpVar::new_witness(ark_relations::ns!(cs, "k_data_1"), || {
            Ok(self.k_data.unwrap())
        })
        .unwrap();

        let k_data_2 =
            <SymmetricEncryptionSchemeGadget<C::BaseField> as SymmetricEncryptionGadget<
                SymmetricEncryptionScheme<C::BaseField>,
                C::BaseField,
            >>::SymmetricKeyVar::new_witness(
                ark_relations::ns!(cs, "k_data_2"),
                || {
                    Ok(symmetric::SymmetricKey {
                        k: self.k_data.unwrap(),
                    })
                },
            )
            .unwrap();

        let randomness: symmetric::Randomness<_> = symmetric::Randomness {
            r: self.ct_r.unwrap(),
        };

        let ct_r = symmetric::constraints::RandomnessVar::<C::BaseField>::new_witness(
            ark_relations::ns!(cs, "r"),
            || Ok(randomness),
        )
        .unwrap();

        // let tmp = MiMCGadget::

        let ct_data: Vec<symmetric::constraints::CiphertextVar<C::BaseField>> = self
            .ct_data
            .clone()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, c)| {
                <SymmetricEncryptionSchemeGadget<C::BaseField> as SymmetricEncryptionGadget<
                    SymmetricEncryptionScheme<C::BaseField>,
                    C::BaseField,
                >>::CiphertextVar::new_witness(
                    ark_relations::ns!(cs, "ct_data{i}"),
                    || {
                        Ok(symmetric::Ciphertext {
                            r: C::BaseField::from_bigint((i as u64).into()).unwrap(),
                            c: *c,
                        })
                    },
                )
                .unwrap()
            })
            .collect();

        let ct_data_2: Vec<FpVar<C::BaseField>> = self
            .ct_data
            .clone()
            .unwrap()
            .iter()
            .map(|(i)| {
                FpVar::new_witness(ark_relations::ns!(cs, "ct_data_2{i}"), || Ok(i)).unwrap()
            })
            .collect();

        //==============================================================================================================

        // h_k_data == Hash(pk_peer_own || k_data)
        let check_h_ct = MiMCGadget::<C::BaseField>::evaluate(
            &rc,
            &[pk_peer_own.clone(), k_data_1.clone()].to_vec(),
        )
        .unwrap();
        // assert_eq!(self.h_ct.unwrap(), check_h_ct.value().unwrap());
        h_k_data.enforce_equal(&check_h_ct).unwrap();

        //==============================================================================================================

        // h_ct = Hash(CT_data)
        let check_h_ct =
            MiMCGadget::<C::BaseField>::evaluate(&rc, ct_data_2.clone().as_ref()).unwrap();

        h_ct.enforce_equal(&check_h_ct).unwrap();

        //==============================================================================================================

        //ct_data = SE.Enc(data,k_data)
        let check_ct_data = SymmetricEncryptionSchemeGadget::<C::BaseField>::encrypt(
            rc.clone(),
            ct_r.clone(),
            k_data_2.clone(),
            symmetric::constraints::PlaintextVar { m: data.clone() },
        )
        .unwrap();

        ct_data_2.enforce_equal(&[check_ct_data.c])
    }
}

#[test]
fn test_Data() {
    println!("{:?}", 11);
}
