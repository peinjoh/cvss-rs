use cvss_rs::v4_0::CvssV4;
use std::str::FromStr;

#[test]
fn test_v4_0_debug_mismatch() {
    // CVE-2024-7657: This vector should calculate to 5.3
    let vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N";
    let cvss = CvssV4::from_str(vector).unwrap();

    let score = cvss.calculated_base_score().unwrap();
    assert_eq!(score, 5.3);
}

#[test]
fn test_v4_0_exploit_maturity_not_defined() {
    // CVE-2025-6829: Vector with E:X (NotDefined) should still calculate to 5.3
    // Previously calculated 1.3 due to bug in merge_exploit_maturity
    let vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:X";
    let cvss = CvssV4::from_str(vector).unwrap();

    let score = cvss.calculated_base_score().unwrap();
    assert_eq!(
        score, 5.3,
        "E:X (NotDefined) should be treated as E:A (Attacked)"
    );

    // CVE-2025-6166: Another E:X case that should calculate to 5.1
    let vector2 = "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:X";
    let cvss2 = CvssV4::from_str(vector2).unwrap();

    let score2 = cvss2.calculated_base_score().unwrap();
    assert_eq!(score2, 5.1, "E:X should be treated as E:A");
}

#[test]
fn test_v4_0_cve_2020_36855() {
    // CVE-2020-36855: Base score should be 4.8 regardless of E metric
    // In CVSS v4.0, base score excludes threat metrics (E) for backwards compatibility
    let vector = "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:P";
    let cvss = CvssV4::from_str(vector).unwrap();

    let score = cvss.calculated_base_score().unwrap();
    assert_eq!(score, 4.8);
}
