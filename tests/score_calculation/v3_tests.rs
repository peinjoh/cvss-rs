use cvss_rs::v3::CvssV3;
use std::str::FromStr;

#[test]
fn test_v3_1_rounding_examples() {
    // CVE-2023-35161: Tests CVSS v3.1 environmental formula changes
    //
    // CVSS v3.1 changed the ENVIRONMENTAL Impact formula (Modified Impact Sub Score):
    // - v3.0: 7.52 × (MISS - 0.029) - 3.25 × (MISS - 0.02)^15
    // - v3.1: 7.52 × (MISS - 0.029) - 3.25 × (MISS × 0.9731 - 0.02)^13
    //
    // The base score formula remained unchanged (still uses exponent 15).
    //
    // References:
    // - https://www.first.org/cvss/v3-1/specification-document#7-3-Environmental-Metrics-Equations
    // - https://www.first.org/cvss/v3-1/user-guide#2-6-Formula-Changes
    //
    // This produces different scores:
    // - Base: 9.6 (same formula for both v3.0 and v3.1)
    // - Temporal: 9.6 (based on base score)
    // - Environmental: 9.7 (v3.1 formula with exponent 13 produces higher score)
    let vector1 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H";
    let cvss1 = CvssV3::from_str(vector1).unwrap();

    let base_score = cvss1.calculated_base_score().unwrap();
    let temporal_score = cvss1.calculated_temporal_score().unwrap();
    let env_score = cvss1.calculated_environmental_score().unwrap();

    assert_eq!(base_score, 9.6, "Base score should be 9.6");
    assert_eq!(
        temporal_score, 9.6,
        "Temporal score should be 9.6 (with E/RL/RC = NotDefined)"
    );
    assert_eq!(env_score, 9.7, "Environmental score should be 9.7 per CVSS v3.1 formula (with all env metrics = NotDefined)");
}

#[test]
fn test_v3_score_calculation() {
    // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    // This is a critical vulnerability with base score 9.8
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    assert_eq!(calculated_score, 9.8);
}

#[test]
fn test_v3_scope_changed_calculation() {
    // CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
    // Scope changed (S:C) with low privileges required
    let vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    // With scope changed, PR:L uses 0.68 instead of 0.62
    assert_eq!(calculated_score, 9.9);
}

#[test]
fn test_v3_temporal_score_calculation() {
    // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let base_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate base score");
    assert_eq!(base_score, 9.8);

    let temporal_score = cvss
        .calculated_temporal_score()
        .expect("Failed to calculate temporal score");
    // Base (9.8) * E(0.94) * RL(0.95) * RC(1.0) = 8.75... -> roundup to 8.8
    assert_eq!(temporal_score, 8.8);
}

#[test]
fn test_v3_environmental_score_calculation() {
    // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let base_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate base score");
    assert_eq!(base_score, 9.8);

    let environmental_score = cvss
        .calculated_environmental_score()
        .expect("Failed to calculate environmental score");
    // With all security requirements set to High (1.5), modified impact is capped at 0.915
    // but the final roundup still results in 9.8
    assert_eq!(environmental_score, 9.8);
}

#[test]
fn test_v3_zero_impact_score() {
    // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N
    // No impact should result in score 0.0
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    assert_eq!(calculated_score, 0.0);
}
