//! One-shot composition of non-secret application settings.
//!
//! Commands and password sources are invocation concerns and deliberately do
//! not appear here. Firmament sees only settings safe to source from command
//! options or the process environment.

use std::error::Error as StdError;
use std::fmt::{self, Display, Formatter};

use bon::Builder;
use clap::Parser;
use firmament::providers::{Env, Serialized};
use firmament::{Figment, Provider};
use serde::{Deserialize, Serialize};

const ENVIRONMENT_PREFIX: &str = "GMELLON_";
const DEFAULT_COLLECTION: &str = "login";

/// Optional command-line overrides for composable settings.
///
/// The top-level CLI flattens this parser while keeping its selected command
/// and password source separate from configuration.
#[derive(Clone, Debug, Default, Deserialize, Parser, Serialize, Builder)]
pub struct Input {
    /// Select COLLECTION when a command does not include an explicit ID.
    #[arg(long, global = true, value_name = "COLLECTION")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_collection: Option<String>,
}

/// Fully resolved, validated application settings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Builder)]
pub struct Settings {
    pub default_collection: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            default_collection: DEFAULT_COLLECTION.to_owned(),
        }
    }
}

/// Configuration composition or validation failed.
#[derive(Debug)]
pub enum Error {
    Compose(Box<firmament::Error>),
    EmptyDefaultCollection,
}

impl Display for Error {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compose(error) => write!(formatter, "could not compose configuration: {error}"),
            Self::EmptyDefaultCollection => {
                formatter.write_str("default collection ID cannot be empty")
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Compose(error) => Some(error.as_ref()),
            Self::EmptyDefaultCollection => None,
        }
    }
}

/// Resolve settings with precedence CLI > `GMELLON_` environment > defaults.
pub fn resolve(input: Input) -> Result<Settings, Error> {
    resolve_with(
        input,
        Env::prefixed(ENVIRONMENT_PREFIX)
            .only(&["default_collection"])
            .ignore_empty(true)
            .parser(parse_environment_value),
    )
}

fn parse_environment_value(value: &str) -> firmament::value::Value {
    firmament::value::Value::from(value.to_owned())
}

fn resolve_with(input: Input, environment: impl Provider) -> Result<Settings, Error> {
    let settings = Figment::new()
        .merge(Serialized::defaults(Settings::default()))
        .merge(environment)
        .merge(Serialized::defaults(input))
        .extract::<Settings>()
        .map_err(|error| Error::Compose(Box::new(error)))?;

    if settings.default_collection.is_empty() {
        return Err(Error::EmptyDefaultCollection);
    }
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Environment<'a> {
        default_collection: &'a str,
    }

    #[test]
    fn defaults_to_login() {
        let settings =
            resolve_with(Input::default(), Serialized::defaults(Input::default())).unwrap();

        assert_eq!(settings.default_collection, "login");
    }

    #[test]
    fn environment_overrides_the_default() {
        let settings = resolve_with(
            Input::default(),
            Serialized::defaults(Environment {
                default_collection: "work",
            }),
        )
        .unwrap();

        assert_eq!(settings.default_collection, "work");
    }

    #[test]
    fn cli_overrides_environment() {
        let settings = resolve_with(
            Input::builder()
                .default_collection("personal".to_owned())
                .build(),
            Serialized::defaults(Environment {
                default_collection: "work",
            }),
        )
        .unwrap();

        assert_eq!(settings.default_collection, "personal");
    }

    #[test]
    fn absent_cli_value_does_not_erase_environment() {
        let input = Input::try_parse_from(["gmellon"]).unwrap();
        let settings = resolve_with(
            input,
            Serialized::defaults(Environment {
                default_collection: "work",
            }),
        )
        .unwrap();

        assert_eq!(settings.default_collection, "work");
    }

    #[test]
    fn numeric_collection_ids_remain_strings() {
        let parsed = parse_environment_value("123");

        assert!(matches!(parsed, firmament::value::Value::String(_, _)));
    }

    #[test]
    fn empty_collection_is_rejected_after_composition() {
        let result = resolve_with(
            Input::builder().default_collection(String::new()).build(),
            Serialized::defaults(Input::default()),
        );

        assert!(matches!(result, Err(Error::EmptyDefaultCollection)));
    }

    #[test]
    fn invalid_provider_types_remain_composition_errors() {
        let result = resolve_with(
            Input::default(),
            Serialized::default("default_collection", 42_u8),
        );

        assert!(matches!(result, Err(Error::Compose(_))));
    }

    #[test]
    fn config_input_contains_no_invocation_or_secret_fields() {
        let value = firmament::value::Value::serialize(
            Input::builder()
                .default_collection("work".to_owned())
                .build(),
        )
        .unwrap();
        let fields = value.into_dict().unwrap();

        assert_eq!(fields.len(), 1);
        assert!(fields.contains_key("default_collection"));
    }
}
