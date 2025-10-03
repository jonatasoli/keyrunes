use regex::Regex;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct Email(String);

impl TryFrom<&str> for Email {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let email_re = Regex::new(r"^[\w.+-]+@[\w-]+\.[\w.-]+$").unwrap();
        if !email_re.is_match(value) {
            anyhow::bail!("invalid email");
        }
        Ok(Self(value.to_owned()))
    }
}

impl<'de> Deserialize<'de> for Email {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let email = String::deserialize(deserializer)?;
        Ok(Self::try_from(email.as_str()).map_err(|e| serde::de::Error::custom(e.to_string()))?)
    }
}

impl ToString for Email {
    fn to_string(&self) -> String {
        self.0.to_owned()
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, Clone)]
pub struct Password(SecretString);

impl TryFrom<&str> for Password {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() < 8 {
            anyhow::bail!("password too short");
        }

        Ok(Self(SecretString::from(value)))
    }
}

impl<'de> Deserialize<'de> for Password {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let password = String::deserialize(deserializer)?;

        Ok(Self::try_from(password.as_str())
            .map_err(|e| serde::de::Error::custom(e.to_string()))?)
    }
}

impl Password {
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}
