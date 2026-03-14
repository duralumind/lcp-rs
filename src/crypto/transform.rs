/// An interface for the secret transform that is applied to the hash of the
/// user's passphrase to decrypt the contents of the publication.
/// To get the content decryption key, we first hash the `UserPassphrase` and then
/// apply the transform to get the transformed encryption key.
///
/// The transform for production readium lcp profiles is not open source and is
/// a secret.
/// Any trusted license providers who wish to implement the production profiles need
/// to implement this trait for the corresponding profile.
///
/// /// This library only implements the transform for the basic encryption profile
/// which is an identity function.
pub trait Transform {
    fn transform(&self, user_key: [u8; 32]) -> [u8; 32];
}
