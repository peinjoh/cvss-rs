use crate::validation_errors::ValidationErrors;

pub trait CvssScoreCalculation {
    fn calculated_base_score(&self) -> Option<f64>;
    fn calculated_temporal_score(&self) -> Option<f64>;

    fn calculated_environmental_score(&self) -> Option<f64>;
}

pub trait CvssValidation {
    fn validate(&self) -> Option<ValidationErrors>;
}
