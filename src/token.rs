use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize, de::{self, Visitor}};
use std::fmt;
use std::ops::Deref;
use sqlx::{Encode, Decode, Type};

const TOKEN_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const TOKEN_LENGTH: usize = 18;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Encode, Decode)]
pub struct Token(String);

impl Token {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let token: String = (0..TOKEN_LENGTH)
            .map(|_| *TOKEN_ALPHABET.as_bytes().choose(&mut rng).unwrap() as char)
            .collect();
        Token(token)
    }

    fn is_valid(s: &str) -> bool {
        s.len() == TOKEN_LENGTH && s.chars().all(|c| TOKEN_ALPHABET.contains(c))
    }
}

impl AsRef<str> for Token {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

use std::str::FromStr;

impl FromStr for Token {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if Self::is_valid(s) {
            Ok(Token(s.to_string()))
        } else {
            Err("Invalid token format")
        }
    }
}

impl<'de> Deserialize<'de> for Token {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

impl Type<sqlx::Sqlite> for Token {
    fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
        <String as Type<sqlx::Sqlite>>::type_info()
    }
}

impl Deref for Token {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_valid_token() {
        let valid_token = "ABCDEFGHIJKLMNOPQR";
        let token: Token = valid_token.parse().unwrap();
        assert_eq!(token.to_string(), valid_token);
    }

    #[test]
    fn test_invalid_token_length() {
        assert!("TOOLONG0123456789".parse::<Token>().is_err());
    }

    #[test]
    fn test_invalid_token_alphabet() {
        assert!("INVALID!TOKEN1234".parse::<Token>().is_err());
    }

    #[test]
    fn test_deserialize_valid_token() {
        let valid_token = "\"ABCDEFGHIJKLMNOPQR\"";
        let token: Token = serde_json::from_str(valid_token).unwrap();
        assert_eq!(token.to_string(), "ABCDEFGHIJKLMNOPQR");
    }

    #[test]
    fn test_deserialize_invalid_token() {
        let invalid_token = "\"INVALID!TOKEN1234\"";
        let result: Result<Token, _> = serde_json::from_str(invalid_token);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_str() {
        let valid_token = "ABCDEFGHIJKLMNOPQR";
        let token = Token::from_str(valid_token).unwrap();
        assert_eq!(token.to_string(), valid_token);

        let invalid_token = "INVALID!TOKEN1234";
        assert!(Token::from_str(invalid_token).is_err());
    }

    #[tokio::test]
    async fn test_sqlx_encode_decode() {
        use sqlx::{Sqlite, Pool};

        let pool = Pool::<Sqlite>::connect("sqlite::memory:").await.unwrap();

        sqlx::query("CREATE TABLE tokens (token TEXT PRIMARY KEY)")
            .execute(&pool)
            .await
            .unwrap();

        let token = Token::new();
        let token_str = token.to_string();

        sqlx::query("INSERT INTO tokens (token) VALUES (?)")
            .bind(&token)
            .execute(&pool)
            .await
            .unwrap();

        let retrieved_token: Token = sqlx::query_scalar("SELECT token FROM tokens")
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_eq!(token, retrieved_token);
        assert_eq!(token_str, retrieved_token.to_string());
    }

    #[test]
    fn test_token_deref() {
        let token = Token::new();
        let token_str: &str = &token; // This now works due to Deref
        assert_eq!(token.0, token_str);

        // We can also use string methods directly on Token
        assert_eq!(token.len(), TOKEN_LENGTH);
        assert!(token.starts_with(|c: char| c.is_ascii_uppercase() || c.is_ascii_digit()));

        // And compare them in Option<_>
        assert!(Some(token_str) == Some(&token));
    }
}
