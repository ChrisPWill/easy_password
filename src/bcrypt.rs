use bcrypt::{hash, verify, BcryptError};
use hmac::{Hmac, Mac};
use sha2::{digest::InvalidLength, Sha256};
use std::fmt::Write;

#[derive(Debug, PartialEq)]
pub enum PasswordError {
    InvalidKeyLength,
    CostNotAllowed(u32),
    InvalidHash(String),
}

fn hmac_password(
    password: &str,
    hmac_key: &[u8],
) -> Result<String, InvalidLength> {
    let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key)?;
    mac.update(password.as_bytes());
    let result = mac.finalize().into_bytes();
    let mut result_hex = String::new();
    write!(&mut result_hex, "{result:x}")
        .expect("The Hmac result should convert to hex.");
    Ok(result_hex)
}

/// HMAC and Bcrypt a password of any arbitrary length
///
/// # Examples
///
/// Usage:
/// ```
/// use easy_password::bcrypt::hash_password;
///
/// let hash = hash_password("my_password", b"secure_key", 12).unwrap();
/// ```
pub fn hash_password(
    password: &str,
    hmac_key: &[u8],
    bcrypt_rounds: u32,
) -> Result<String, PasswordError> {
    let hmac_hex = match hmac_password(password, hmac_key) {
        Ok(result) => result,
        Err(InvalidLength) => {
            return Err(PasswordError::InvalidKeyLength);
        }
    };
    let hashed = hash(hmac_hex.as_str(), bcrypt_rounds);
    match hashed {
        Ok(result) => Ok(result),
        Err(BcryptError::CostNotAllowed(cost)) => {
            Err(PasswordError::CostNotAllowed(cost))
        }
        Err(error) => panic!("Unexpected Bcrypt error {}.", error),
    }
}

/// HMAC and Bcrypt a password of any arbitrary length
///
/// # Examples
///
/// Usage:
/// ```
/// use easy_password::bcrypt::{hash_password, verify_password};
///
/// let hash = hash_password("my_password", b"secure_key", 12).unwrap();
/// let result =
///     verify_password("my_password", hash.as_str(), b"secure_key").unwrap();
/// ```
pub fn verify_password(
    password: &str,
    hashed: &str,
    hmac_key: &[u8],
) -> Result<bool, PasswordError> {
    let hmac_hex = match hmac_password(password, hmac_key) {
        Ok(result) => result,
        Err(InvalidLength) => {
            return Err(PasswordError::InvalidKeyLength);
        }
    };
    match verify(hmac_hex.as_str(), hashed) {
        Ok(bool) => Ok(bool),
        Err(BcryptError::InvalidCost(_))
        | Err(BcryptError::InvalidPrefix(_))
        | Err(BcryptError::InvalidHash(_))
        | Err(BcryptError::InvalidBase64(..)) => {
            Err(PasswordError::InvalidHash(hashed.to_string()))
        }
        Err(error) => panic!("Unexpected Bcrypt error {}.", error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_correct() {
        let hash = hash_password("test_password", b"my_key", 4)
            .expect("This should be a valid cost and hmac_key");
        assert!(
            verify_password("test_password", hash.as_str(), b"my_key")
                .expect("Hash and hmac_key should be valid.")
        );
    }

    #[test]
    fn test_verify_incorrect() {
        let hash = hash_password("test_password", b"my_key", 4)
            .expect("This should be a valid cost and hmac_key");
        assert!(
            !verify_password("wrong_password", hash.as_str(), b"my_key")
                .expect("Hash and hmac_key should be valid.")
        );
    }

    #[test]
    fn test_invalid_cost() {
        assert_eq!(
            hash_password("test_password", b"my_key", 1).err(),
            Some(PasswordError::CostNotAllowed(1)),
        );
    }

    #[test]
    fn test_invalid_hash() {
        assert_eq!(
            verify_password("wrong_password", "invalid_hash", b"my_key").err(),
            Some(PasswordError::InvalidHash("invalid_hash".to_string())),
        );
    }
}
