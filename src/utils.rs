pub mod gocore_compat {
    use ethereum_types::{H176 as Address, H160};
    use tiny_keccak::{Hasher, Sha3};
    use libgoldilocks::{VerifyingKey, SigningKey};
    use corebc_core::{utils::to_ican, types::Network};
    use crate::KeystoreError;

    /// Converts a K256 SigningKey to an Ethereum Address
    pub fn address_from_pk<S>(pk: S, network: &Network) -> Result<Address, KeystoreError>
    where
        S: AsRef<[u8]>,
    {
        let secret_key = SigningKey::from_bytes(pk.as_ref())?;
        let public_key = VerifyingKey::from(*secret_key.verifying_key());
        let public_key = public_key.as_bytes();

        let hash = sha3(&public_key[..]);
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&hash[12..]);
        let addr = H160::from(bytes);
        Ok(to_ican(&addr, network))
    }

    /// Compute the Keccak-256 hash of input bytes.
pub fn sha3<T: AsRef<[u8]>>(bytes: T) -> [u8; 32] {
    let mut output = [0u8; 32];

    let mut hasher = Sha3::v256();
    hasher.update(bytes.as_ref());
    hasher.finalize(&mut output);

    output
}
}
