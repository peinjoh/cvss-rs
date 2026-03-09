use cvss_rs::v3::CvssV3;
use std::str::FromStr;

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

#[test]
fn test_v3_cve_with_explicit_not_defined() {
    // This vector is based on an issue brought up here: https://github.com/scm-rs/cvss-rs/issues/9
    // This tests that explicit `NotDefined` / `X` values in the modified metrics used in the
    // environmental score calculation are handled correctly / like implicit
    // "NotDefined" values caused by absence in the vector string.
    let vector =
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/MAV:A/MAC:L/MPR:N/MUI:X/MS:U/CR:L/IR:H/AR:X";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let base_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate base score");

    let temporal_score = cvss
        .calculated_temporal_score()
        .expect("Failed to calculate temporal score");

    let environmental_score = cvss
        .calculated_environmental_score()
        .expect("Failed to calculate environmental score");

    assert_eq!(base_score, 7.8);
    assert_eq!(temporal_score, 7.8);
    assert_eq!(environmental_score, 8.0);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.0 CVE-2013-1937](https://www.first.org/cvss/v3.0/examples#phpMyAdmin-Reflected-Cross-site-Scripting-Vulnerability-CVE-2013-1937)
#[test]
fn test_v3_real_cve_2013_1937() {
    let vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 6.1);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2013-0375](https://www.first.org/cvss/v3.1/examples#MySQL-Stored-SQL-Injection-CVE-2013-0375)
#[test]
fn test_v3_real_cve_2013_0375() {
    let vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 6.4);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2014-3566](https://www.first.org/cvss/v3.1/examples#SSLv3-POODLE-Vulnerability-CVE-2014-3566)
#[test]
fn test_v3_real_cve_2014_3566() {
    let vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 3.1);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2012-1516](https://www.first.org/cvss/v3.1/examples#VMware-Guest-to-Host-Escape-Vulnerability-CVE-2012-1516)
#[test]
fn test_v3_real_cve_2012_1516() {
    let vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 9.9);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2009-0783](https://www.first.org/cvss/v3.1/examples#Apache-Tomcat-XML-Parser-Vulnerability-CVE-2009-0783)
#[test]
fn test_v3_real_cve_2009_0783() {
    let vector = "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 4.2);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.0 CVE-2012-0384](https://www.first.org/cvss/v3.0/examples#Cisco-IOS-Arbitrary-Command-Execution-Vulnerability-CVE-2012-0384)
///
/// This was re-scored in CVSS v3.1.
#[test]
fn test_v3_0_real_cve_2012_0384() {
    let vector = "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 8.8);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2012-0384](https://www.first.org/cvss/v3.1/examples#Cisco-IOS-Arbitrary-Command-Execution-Vulnerability-CVE-2012-0384)
///
/// v3.1 re-scored PR:L → PR:H, resulting in score 7.2 instead of 8.8.
#[test]
fn test_v3_1_real_cve_2012_0384() {
    let vector = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 7.2);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2015-1098](https://www.first.org/cvss/v3.1/examples#Apple-iWork-Denial-of-Service-Vulnerability-CVE-2015-1098)
///
/// The same vector was also defined for:
/// [first.org v3.1 CVE-2009-0658](https://www.first.org/cvss/v3.1/examples#Adobe-Acrobat-Buffer-Overflow-Vulnerability-CVE-2009-0658)
/// [first.org v3.1 CVE-2018-18913](https://www.first.org/cvss/v3.1/examples#Opera-DLL-search-order-hijacking-CVE-2018-18913)
#[test]
fn test_v3_real_cve_2015_1098() {
    let vector = "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 7.8);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2014-0160](https://www.first.org/cvss/v3.1/examples#OpenSSL-Heartbleed-Vulnerability-CVE-2014-0160)
#[test]
fn test_v3_real_cve_2014_0160() {
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 7.5);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2014-6271](https://www.first.org/cvss/v3.1/examples#GNU-Bourne-Again-Shell-Bash-Shellshock-Vulnerability-CVE-2014-6271)
#[test]
fn test_v3_real_cve_2014_6271() {
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 9.8);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2008-1447](https://www.first.org/cvss/v3.1/examples#DNS-Kaminsky-Bug-CVE-2008-1447)
#[test]
fn test_v3_real_cve_2008_1447() {
    let vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 6.8);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2014-2005](https://www.first.org/cvss/v3.1/examples#Sophos-Login-Screen-Bypass-Vulnerability-CVE-2014-2005)
#[test]
fn test_v3_real_cve_2014_2005() {
    let vector = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 6.8);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2010-0467](https://www.first.org/cvss/v3.1/examples#Joomla-Directory-Traversal-Vulnerability-CVE-2010-0467)
#[test]
fn test_v3_real_cve_2010_0467() {
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 5.8);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2012-1342](https://www.first.org/cvss/v3.1/examples#Cisco-Access-Control-Bypass-Vulnerability-CVE-2012-1342)
#[test]
fn test_v3_real_cve_2012_1342() {
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 5.8);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2013-6014](https://www.first.org/cvss/v3.1/examples#Juniper-Proxy-ARP-Denial-of-Service-Vulnerability-CVE-2013-6014)
#[test]
fn test_v3_real_cve_2013_6014() {
    let vector = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 9.3);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.0 CVE-2014-9253](https://www.first.org/cvss/v3.0/examples#DokuWiki-Reflected-Cross-site-Scripting-Attack-CVE-2014-9253)
#[test]
fn test_v3_real_cve_2014_9253() {
    let vector = "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 5.4);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2011-1265](https://www.first.org/cvss/v3.1/examples#Microsoft-Windows-Bluetooth-Remote-Code-Execution-Vulnerability-CVE-2011-1265)
#[test]
fn test_v3_real_cve_2011_1265() {
    let vector = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 8.8);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2014-2019](https://www.first.org/cvss/v3.1/examples#Apple-iOS-Security-Control-Bypass-Vulnerability-CVE-2014-2019)
#[test]
fn test_v3_real_cve_2014_2019() {
    let vector = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 4.6);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2015-0970](https://www.first.org/cvss/v3.1/examples#SearchBlox-Cross-Site-Request-Forgery-Vulnerability-CVE-2015-0970)
///
/// The same vector was also defined for:
/// [first.org v3.1 CVE-2016-1645](https://www.first.org/cvss/v3.1/examples#Google-Chrome-PDFium-JPEG-2000-Remote-Code-Execution-Vulnerability-CVE-2016-1645)
#[test]
fn test_v3_real_cve_2015_0970() {
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 8.8);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2014-0224](https://www.first.org/cvss/v3.1/examples#SSL-TLS-MITM-Vulnerability-CVE-2014-0224)
#[test]
fn test_v3_real_cve_2014_0224() {
    let vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 7.4);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2012-5376](https://www.first.org/cvss/v3.1/examples#Google-Chrome-Sandbox-Bypass-vulnerability-CVE-2012-5376)
#[test]
fn test_v3_real_cve_2012_5376() {
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 9.6);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2016-0128](https://www.first.org/cvss/v3.1/examples#SAMR-LSAD-Privilege-Escalation-via-Protocol-Downgrade-Vulnerability-Badlock-CVE-2016-0128-and-CVE-2016-2118)
#[test]
fn test_v3_real_cve_2016_0128() {
    let vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 6.8);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2016-2118](https://www.first.org/cvss/v3.1/examples#SAMR-LSAD-Privilege-Escalation-via-Protocol-Downgrade-Vulnerability-Badlock-CVE-2016-0128-and-CVE-2016-2118)
///
/// The same vector was also defined for:
/// [first.org v3.1 CVE-2019-0884](https://www.first.org/cvss/v3.1/examples#Scripting-Engine-Memory-Corruption-Vulnerability-CVE-2019-0884) (Internet Explorer 11)
#[test]
fn test_v3_real_cve_2016_2118() {
    let vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 7.5);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2019-7551](https://www.first.org/cvss/v3.1/examples#Cantemo-Portal-Stored-Cross-site-Scripting-Vulnerability-CVE-2019-7551)
#[test]
fn test_v3_real_cve_2019_7551() {
    let vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 9.0);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2017-5942](https://www.first.org/cvss/v3.1/examples#WordPress-Mail-Plugin-Reflected-Cross-site-Scripting-Vulnerability-CVE-2017-5942)
#[test]
fn test_v3_real_cve_2017_5942() {
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 6.1);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2016-5558](https://www.first.org/cvss/v3.1/examples#Remote-Code-Execution-in-Oracle-Outside-in-Technology-CVE-2016-5558)
#[test]
fn test_v3_real_cve_2016_5558() {
    let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 8.6);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2016-5729](https://www.first.org/cvss/v3.1/examples#Lenovo-ThinkPwn-Exploit-CVE-2016-5729)
#[test]
fn test_v3_real_cve_2016_5729() {
    let vector = "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 8.2);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2015-2890](https://www.first.org/cvss/v3.1/examples#Failure-to-Lock-Flash-on-Resume-from-sleep-CVE-2015-2890)
#[test]
fn test_v3_real_cve_2015_2890() {
    let vector = "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 6.0);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2018-3652](https://www.first.org/cvss/v3.1/examples#Intel-DCI-Issue-CVE-2018-3652)
#[test]
fn test_v3_real_cve_2018_3652() {
    let vector = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 7.6);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org v3.1 CVE-2019-0884 on Microsoft Edge](https://www.first.org/cvss/v3.1/examples#Scripting-Engine-Memory-Corruption-Vulnerability-CVE-2019-0884)
#[test]
fn test_v3_real_cve_2019_0884_edge() {
    let vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N";
    let cvss = CvssV3::from_str(vector).expect("Failed to parse CVSS v3.1 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 4.2);
}
