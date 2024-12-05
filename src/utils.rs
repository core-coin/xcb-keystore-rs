pub mod gocore_compat {
    use crate::KeystoreError;
    use base_core::primitives::IcanAddress;
    use libgoldilocks::SigningKey;

    /// Converts a K256 SigningKey to an Core Address
    pub fn address_from_pk<S>(pk: S, network: u64) -> Result<IcanAddress, KeystoreError>
    where
        S: AsRef<[u8]>,
    {
        let signing_key =
            SigningKey::from_bytes(pk.as_ref()).map_err(|e| KeystoreError::GoldilocksError(e))?;
        Ok(IcanAddress::from_private_key(&signing_key, network))
    }
}
