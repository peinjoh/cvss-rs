use cvss_rs as cvss;
use cvss_rs::traits::CvssValidation;
use cvss_rs::Cvss;
use cvss_rs::validation_errors::{JsonValidationError, ScoreValidationError, ValidationErrors};

#[test]
pub fn test_v2_base_score_correct() {
    let input_json = include_str!("v2_0_data/v2_0_base_score_correct.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    if let Cvss::V2(cvss_v2) = &cvss {
        assert_eq!(cvss_v2.validate(), None);
    } else {
        panic!("Expected Cvss::V2 variant");
    }
}

#[test]
pub fn test_v2_base_score_calc_failed() {
    let input_json = include_str!("v2_0_data/v2_0_base_score_calc_failed.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    if let Cvss::V2(cvss_v2) = &cvss {
        assert_eq!(
            cvss_v2.validate(),
            Some(ValidationErrors {
                vector_parse_errors: None,
                json_validation_errors: None,
                score_validation_errors: Some(vec![
                    ScoreValidationError::BaseScoreCalculationFromVectorFailed,
                    ScoreValidationError::TemporalScoreCalculationFromVectorFailed,
                    ScoreValidationError::EnvironmentalScoreCalculationFromVectorFailed
                ]),
            })
        );
    } else {
        panic!("Expected Cvss::V2 variant");
    }
}

#[test]
pub fn test_v2_base_score_wrong_calc() {
    let input_json = include_str!("v2_0_data/v2_0_base_score_wrong_calc.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    if let Cvss::V2(cvss_v2) = &cvss {
        assert_eq!(
            cvss_v2.validate(),
            Some(ValidationErrors {
                vector_parse_errors: None,
                json_validation_errors: None,
                score_validation_errors: Some(vec![ScoreValidationError::BaseScoreMismatch {
                    from_vector: 7.8,
                    found_json: 10.0
                }]),
            })
        );
    } else {
        panic!("Expected Cvss::V2 variant");
    }
}

#[test]
pub fn test_v2_temp_score_correct() {
    let input_json = include_str!("v2_0_data/v2_0_temp_score_correct.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    if let Cvss::V2(cvss_v2) = &cvss {
        assert_eq!(cvss_v2.validate(), None);
    } else {
        panic!("Expected Cvss::V2 variant");
    }
}

#[test]
pub fn test_v2_temp_score_calc_wrong() {
    let input_json = include_str!("v2_0_data/v2_0_temp_score_wrong_calc.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    if let Cvss::V2(cvss_v2) = &cvss {
        assert_eq!(
            cvss_v2.validate(),
            Some(ValidationErrors {
                vector_parse_errors: None,
                json_validation_errors: None,
                score_validation_errors: Some(vec![ScoreValidationError::TemporalScoreMismatch {
                    from_vector: 6.4,
                    from_json: 8.0
                }]),
            })
        );
    } else {
        panic!("Expected Cvss::V2 variant");
    }
}

#[test]
pub fn test_v2_env_score_correct() {
    let input_json = include_str!("v2_0_data/v2_0_env_score_correct.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    if let Cvss::V2(cvss_v2) = &cvss {
        assert_eq!(cvss_v2.validate(), None);
    } else {
        panic!("Expected Cvss::V2 variant");
    }
}

#[test]
pub fn test_v2_env_score_wrong_calc() {
    let input_json = include_str!("v2_0_data/v2_0_env_score_wrong_calc.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    if let Cvss::V2(cvss_v2) = &cvss {
        assert_eq!(
            cvss_v2.validate(),
            Some(ValidationErrors {
                vector_parse_errors: None,
                json_validation_errors: None,
                score_validation_errors: Some(vec![
                    ScoreValidationError::EnvironmentalScoreMismatch {
                        from_vector: 9.2,
                        from_json: 8.0
                    }
                ]),
            })
        );
    } else {
        panic!("Expected Cvss::V2 variant");
    }
}

#[test]
pub fn test_v2_value_conflict() {
    let input_json = include_str!("v2_0_data/v2_0_value_conflict.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    if let Cvss::V2(cvss_v2) = &cvss {
        assert_eq!(
            cvss_v2.validate(),
            Some(ValidationErrors {
                vector_parse_errors: None,
                json_validation_errors: Some(vec![JsonValidationError::ConflictingMetricValues {
                    metric: "Access Vector".to_string(),
                    val_from_json: "L".to_string(),
                    val_from_vector: "N".to_string(),
                }]),
                score_validation_errors: None
            })
        );
    } else {
        panic!("Expected Cvss::V2 variant");
    }
}

#[test]
pub fn test_v2_metric_missing_in_network() {
    let input_json = include_str!("v2_0_data/v2_0_metric_missing_in_vector.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    if let Cvss::V2(cvss_v2) = &cvss {
        assert_eq!(
            cvss_v2.validate(),
            Some(ValidationErrors {
                vector_parse_errors: None,
                json_validation_errors: Some(vec![
                    JsonValidationError::MetricProvidedInJsonButMissingInVector {
                        metric: "Access Vector".to_string(),
                    }
                ]),
                // This is a direct consequence of the missing metric in the vector
                score_validation_errors: Some(vec![
                    ScoreValidationError::BaseScoreCalculationFromVectorFailed,
                    ScoreValidationError::TemporalScoreCalculationFromVectorFailed,
                    ScoreValidationError::EnvironmentalScoreCalculationFromVectorFailed
                ])
            })
        );
    } else {
        panic!("Expected Cvss::V2 variant");
    }
}
