pub mod gocore_compat {
    use crate::KeystoreError;
    use alloy_core::primitives::IcanAddress;

    /// Converts a K256 SigningKey to an Core Address
    pub fn address_from_pk<S>(pk: S, network: u64) -> Result<IcanAddress, KeystoreError>
    where
        S: AsRef<[u8]>,
    {
        println!("{:#?}", pk.as_ref());
        Ok(IcanAddress::from_raw_public_key(pk.as_ref(), network))
    }
}
