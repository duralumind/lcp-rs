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
/// This library only implements the transform for the basic encryption profile
/// which is an identity function.
pub trait Transform {
    fn transform(&self, user_key: [u8; 32]) -> [u8; 32];
}

impl<T: Transform + ?Sized> Transform for &T {
    fn transform(&self, user_key: [u8; 32]) -> [u8; 32] {
        (**self).transform(user_key)
    }
}

/// Resolves a profile URI (from the license document) to the corresponding
/// [`Transform`] implementation.
///
/// Implement this trait to support additional encryption profiles. The resolver
/// is passed to [`decrypt_epub`](crate::decrypt_epub) and [`encrypt_epub`](crate::encrypt_epub)
/// and is called with the profile URI. Return the appropriate `Transform` for
/// that profile, or an error string if the profile is unsupported.
///
/// # Example
///
/// ```
/// use lcp_core::{Transform, TransformResolver, BasicTransform};
///
/// struct SuperSafeTransform;
/// impl Transform for SuperSafeTransform {
///     fn transform(&self, user_key: [u8; 32]) -> [u8; 32] {
///         let mut new_key = user_key.clone();
///         new_key.reverse();
///         new_key
///     }
/// }
///
/// pub struct SuperSafeResolver;
/// impl TransformResolver for SuperSafeResolver {
///     fn resolve(&self, profile_uri: &str) -> Result<Box<dyn Transform>, String> {
///         match profile_uri {
///             "http://readium.org/lcp/basic-profile" => Ok(Box::new(BasicTransform)),
///             "http://mysite.xyz/lcp/super-safe-profile" => Ok(Box::new(SuperSafeTransform)),
///             other => Err(format!("Unknown profile: {}", other)),
///         }
///     }
/// }
/// ```
pub trait TransformResolver {
    fn resolve(&self, profile_uri: &str) -> Result<Box<dyn Transform>, String>;
}

/// Identity transform used by the basic LCP profile.
pub struct BasicTransform;

impl Transform for BasicTransform {
    fn transform(&self, user_key: [u8; 32]) -> [u8; 32] {
        user_key
    }
}

/// Default resolver that only supports the basic LCP profile
/// (`http://readium.org/lcp/basic-profile`).
pub struct BasicResolver;

impl TransformResolver for BasicResolver {
    fn resolve(&self, profile_uri: &str) -> Result<Box<dyn Transform>, String> {
        match profile_uri {
            "http://readium.org/lcp/basic-profile" => Ok(Box::new(BasicTransform)),
            other => Err(format!("Unknown encryption profile: {}", other)),
        }
    }
}
