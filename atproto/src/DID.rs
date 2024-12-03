//! An implementation of the subset of Decentralised Identifiers used by atproto
//!
//! The DID paper is available [here](<https://www.w3.org/TR/did-core>)
//!
//! The ATProto subset is described [here](<https://atproto.com/specs/did>)

use std::ops::Bound;
use thiserror::Error;

type SelfIndex = (Bound<usize>, Bound<usize>);

#[derive(Debug, PartialEq)]
/// Wrapper struct around a DID identifier string
pub struct Did {
    inner: String,
}

#[derive(Debug, Error, PartialEq)]
/// Errors in validation of a DID identifier under ATProto
pub enum DidValidationError {
    #[error("Expected an identifier of at least 9 chars")]
    TooShort,
    #[error("Expected a prefix of did: - found {found}")]
    InvalidPrefix{found: String},
    #[error("Expected a method of either web or plc - found {found}")]
    InvalidMethod{found: String},
    #[error("Identifier didn't conform to DID identifier format - found {found}")]
    InvalidIdentifier{found: String}
}

/// The two ATProto DID methods
#[derive(Debug)]
pub enum DidMethod {
    Web,
    Plc
}

impl Did {
    pub fn try_create(id: String) -> Result<Did, DidValidationError> {
        use DidValidationError::*;
        // did:<method>:<id> is at least 9 bytes for all ATProto supported DID methods 
        if id.len() <= 8 {
            return Err(TooShort)
        }

        // Given the previous error it's not guaranteed that no panics will occur for these slices
        if &id[0..4] != "did:"{
            return Err(InvalidPrefix{found: id[0..4].to_string()})
        }
        
        // These are the only allowed methods for ATProto, simplifying parsing
        if &id[4..8] != "web:" && &id[4..8] != "plc:"{
            return Err(InvalidMethod{found: id[4..8].to_string()})
        }

        if !id[8..].chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == ':' || c == '-'
        }) || id.chars().last() == Some(':') {
            return Err(InvalidIdentifier{found: id[8..].to_string()})
        }

        Ok(Did{inner: id})
    }

    /// Get the method of this DID
    ///
    /// Assumes that the method is one of the two ATProto supported ones
    /// and that the ID has been validated
    pub fn method(&self) -> DidMethod {
         match &self.inner[4..7] {
            "web" => DidMethod::Web,
            "plc" => DidMethod::Plc,
            _ => panic!("An incorrect DID method snuck its way in {self:?}")
        }
    }

    /// Get the identifier of this DID
    /// 
    /// Assumes that `self` is validated correctly and in particular that identifier is not "" and
    /// that the method is three characters long
    pub fn identifier<'a>(&'a self) -> &'a str {
        &self.inner[8..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_web() {
        let did = "did:web:localhost";
        assert_eq!(Did::try_create(did.to_string()), Ok(Did{inner: did.to_string()}))
    }

    #[test]
    fn valid_plc() {
        let did = "did:plc:z72i7hdynmk6r22z27h6tvur";
        assert_eq!(Did::try_create(did.to_string()), Ok(Did{inner: did.to_string()}))
    }

    #[test]
    fn invalid_method() {
        let did = "did:key:zQ3shZc2QzApp2oymGvQbzP8eKheVshBHbU4ZYjeXqwSKEn6N";
        assert_eq!(Did::try_create(did.to_string()), Err(DidValidationError::InvalidMethod{found:"key:".to_string()}))
    }

    #[test]
    fn invalid_syntax() {
        let did = "did:method:val#two";
        assert!(Did::try_create(did.to_string()).is_err())
    }

    #[test]
    fn invalid_empty_id() {
        let did = "did:web:";
        assert_eq!(Did::try_create(did.to_string()), Err(DidValidationError::TooShort))
    }
}
