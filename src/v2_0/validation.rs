use crate::traits::{CvssScoreCalculation, CvssValidation};
use crate::v2_0::CvssV2;
use crate::validation_errors::{JsonValidationError, ScoreValidationError, ValidationErrors};
use std::str::FromStr;

impl CvssValidation for CvssV2 {
    fn validate(&self) -> Option<ValidationErrors> {
        let res = CvssV2::from_str(&self.vector_string);
        let from_vector = match res {
            Ok(cvss_v2) => cvss_v2,
            Err(error) => {
                return Some(ValidationErrors {
                    vector_parse_errors: Some(error),
                    json_validation_errors: None,
                    score_validation_errors: None,
                })
            }
        };
        let json_validation_errors = CvssV2::validate_json(self, &from_vector);
        let score_validation_errors = CvssV2::validate_scores(self, &from_vector);

        if json_validation_errors.is_some() || score_validation_errors.is_some() {
            return Some(ValidationErrors {
                vector_parse_errors: None,
                json_validation_errors,
                score_validation_errors,
            });
        }

        None
    }
}

impl CvssV2 {
    fn validate_json(raw: &CvssV2, from_vector: &CvssV2) -> Option<Vec<JsonValidationError>> {
        macro_rules! validate_field {
            ($errors:expr, $raw:expr, $from_vector:expr, $field:ident, $name:expr) => {
                match (&$raw.$field, &$from_vector.$field) {
                    (Some(raw_val), Some(vec_val)) => {
                        if raw_val != vec_val {
                            $errors.get_or_insert_with(Vec::new).push(
                                JsonValidationError::ConflictingMetricValues {
                                    metric: $name.to_string(),
                                    val_from_json: raw_val.to_string(),
                                    val_from_vector: vec_val.to_string(),
                                },
                            );
                        }
                    }
                    (Some(_), None) => {
                        $errors.get_or_insert_with(Vec::new).push(
                            JsonValidationError::MetricProvidedInJsonButMissingInVector {
                                metric: $name.to_string(),
                            },
                        );
                    }
                    _ => {}
                }
            };
        }

        let mut errors: Option<Vec<JsonValidationError>> = None;

        // Base Metrics
        validate_field!(errors, raw, from_vector, access_vector, "Access Vector");
        validate_field!(
            errors,
            raw,
            from_vector,
            access_complexity,
            "Access Complexity"
        );
        validate_field!(errors, raw, from_vector, authentication, "Authentication");
        validate_field!(
            errors,
            raw,
            from_vector,
            confidentiality_impact,
            "Confidentiality Impact"
        );
        validate_field!(
            errors,
            raw,
            from_vector,
            integrity_impact,
            "Integrity Impact"
        );
        validate_field!(
            errors,
            raw,
            from_vector,
            availability_impact,
            "Availability Impact"
        );

        // Temporal Metrics
        validate_field!(errors, raw, from_vector, exploitability, "Exploitability");
        validate_field!(
            errors,
            raw,
            from_vector,
            remediation_level,
            "Remediation Level"
        );
        validate_field!(
            errors,
            raw,
            from_vector,
            report_confidence,
            "Report Confidence"
        );

        // Environmental Metrics
        validate_field!(
            errors,
            raw,
            from_vector,
            collateral_damage_potential,
            "Collateral Damage Potential"
        );
        validate_field!(
            errors,
            raw,
            from_vector,
            target_distribution,
            "Target Distribution"
        );
        validate_field!(
            errors,
            raw,
            from_vector,
            confidentiality_requirement,
            "Confidentiality Requirement"
        );
        validate_field!(
            errors,
            raw,
            from_vector,
            integrity_requirement,
            "Integrity Requirement"
        );
        validate_field!(
            errors,
            raw,
            from_vector,
            availability_requirement,
            "Availability Requirement"
        );

        errors
    }

    /// Validates that the scores (base, temporal, environmental) provided in the JSON match the
    /// scores calculated from the vector string. If there is a mismatch, a ValidationError is returned.
    fn validate_scores(raw: &CvssV2, from_vector: &CvssV2) -> Option<Vec<ScoreValidationError>> {
        let mut errors: Option<Vec<ScoreValidationError>> = None;

        // Calculate the base score from the vector string
        // As the scores are building upon each other, if the base score can not be calculated
        // we can return early with errors for temporal and environmental score as well.
        let from_vector_base_score = match from_vector.calculated_base_score() {
            None => {
                return Some(vec![
                    ScoreValidationError::BaseScoreCalculationFromVectorFailed,
                    ScoreValidationError::TemporalScoreCalculationFromVectorFailed,
                    ScoreValidationError::EnvironmentalScoreCalculationFromVectorFailed,
                ]);
            }
            Some(base_score) => Some(base_score),
        };

        // Check if the json base score matches the base score calculated from the vector string
        if let Some(base_score) = from_vector_base_score {
            if raw.base_score != base_score {
                errors
                    .get_or_insert_with(Vec::new)
                    .push(ScoreValidationError::BaseScoreMismatch {
                        from_vector: base_score,
                        found_json: raw.base_score,
                    });
            }
        }

        // Check if a temporal score was provided, if not, we do not need to validate it
        if let Some(raw_temporal) = raw.temporal_score {
            // Calculate the temporal score from the vector string
            // Same as above. The environmental score calculation depends on the temporal score,
            // so if the temporal score can not be calculated we can return early
            // with an error for the environmental score as well.
            let from_vector_temporal_score = match from_vector.calculated_temporal_score() {
                None => {
                    errors.get_or_insert_with(Vec::new).extend([
                        ScoreValidationError::TemporalScoreCalculationFromVectorFailed,
                        ScoreValidationError::EnvironmentalScoreCalculationFromVectorFailed,
                    ]);
                    return errors;
                }
                Some(temporal_score) => Some(temporal_score),
            };

            // Check if the json temporal score matches the temporal score calculated from the vector string
            if let Some(temporal_score) = from_vector_temporal_score {
                if raw_temporal != temporal_score {
                    errors.get_or_insert_with(Vec::new).push(
                        ScoreValidationError::TemporalScoreMismatch {
                            from_vector: temporal_score,
                            from_json: raw_temporal,
                        },
                    );
                }
            }
        }

        // Check if an environmental score was provided, if not, we do not need to validate it
        if let Some(raw_environmental) = raw.environmental_score {
            // Calculate the environmental score from the vector string
            let from_vector_environmental_score = match from_vector.calculated_environmental_score()
            {
                None => {
                    errors
                        .get_or_insert_with(Vec::new)
                        .push(ScoreValidationError::EnvironmentalScoreCalculationFromVectorFailed);
                    return errors;
                }
                Some(environmental_score) => Some(environmental_score),
            };

            if let Some(environmental_score) = from_vector_environmental_score {
                if raw_environmental != environmental_score {
                    errors.get_or_insert_with(Vec::new).push(
                        ScoreValidationError::EnvironmentalScoreMismatch {
                            from_vector: environmental_score,
                            from_json: raw_environmental,
                        },
                    );
                }
            }
        }
        errors
    }
}
