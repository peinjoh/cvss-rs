use std::fmt;
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, PartialEq)]
pub struct ValidationErrors {
    pub vector_parse_errors: Option<VectorParseError>,
    pub json_validation_errors: Option<Vec<JsonValidationError>>,
    pub score_validation_errors: Option<Vec<ScoreValidationError>>,
}

/// Errors that can occur when parsing CVSS vector strings.
#[derive(Clone, Debug, PartialEq)]
pub enum VectorParseError {
    /// Vector string doesn't start with "CVSS" or expected prefix
    InvalidPrefix { found: String },
    /// Unsupported or invalid CVSS version
    InvalidVersion { version: String },
    /// Component is malformed (not in key:value format)
    InvalidComponent { component: String },
    /// Metric abbreviation not recognized
    UnknownMetric { metric: String },
    /// Metric value parsing failed
    InvalidMetricValue { metric: String, value: String },
    /// Required base metric is missing
    MissingRequiredMetric { metric: String },
    /// Same metric appears multiple times
    DuplicateMetric { metric: String },
}

#[derive(Clone, Debug, PartialEq)]
pub enum JsonValidationError {
    /// Metric is missing in the vector but provided in the JSON
    MetricProvidedInJsonButMissingInVector { metric: String },
    /// Between the vector and the json, the same metric has different values
    ConflictingMetricValues {
        metric: String,
        val_from_json: String,
        val_from_vector: String,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum ScoreValidationError {
    /// Base Score calculation from vector failed
    BaseScoreCalculationFromVectorFailed,
    /// Temporal Score calculation from vector failed
    TemporalScoreCalculationFromVectorFailed,
    /// Environmental Score calculation from vector failed
    EnvironmentalScoreCalculationFromVectorFailed,
    /// Set base score and base score calculated from the vector string do not match
    BaseScoreMismatch { from_vector: f64, found_json: f64 },
    /// Set temporal score and temporal score calculated from the vector string do not match
    TemporalScoreMismatch { from_vector: f64, from_json: f64 },
    /// Set environmental score and environmental score calculated from the vector string do not match
    EnvironmentalScoreMismatch { from_vector: f64, from_json: f64 },
}

impl Display for VectorParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            VectorParseError::InvalidPrefix { found } => {
                write!(
                    f,
                    "invalid vector prefix: expected 'CVSS', found '{}'",
                    found
                )
            }
            VectorParseError::InvalidVersion { version } => {
                write!(f, "invalid or unsupported CVSS version: '{}'", version)
            }
            VectorParseError::InvalidComponent { component } => {
                write!(
                    f,
                    "invalid component format: '{}' (expected 'KEY:VALUE')",
                    component
                )
            }
            VectorParseError::UnknownMetric { metric } => {
                write!(f, "unknown metric abbreviation: '{}'", metric)
            }
            VectorParseError::InvalidMetricValue { metric, value } => {
                write!(f, "invalid value '{}' for metric '{}'", value, metric)
            }
            VectorParseError::MissingRequiredMetric { metric } => {
                write!(f, "missing required metric: '{}'", metric)
            }
            VectorParseError::DuplicateMetric { metric } => {
                write!(f, "duplicate metric: '{}'", metric)
            }
        }
    }
}

impl std::error::Error for VectorParseError {}
