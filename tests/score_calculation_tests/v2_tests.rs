use cvss_rs::v2_0::CvssV2;
use std::str::FromStr;

#[test]
fn test_v2_score_calculation() {
    // AV:N/AC:L/Au:N/C:C/I:C/A:C
    // This is a high severity vulnerability
    let vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    assert_eq!(calculated_score, 10.0);
}

#[test]
fn test_v2_partial_impact_calculation() {
    // AV:N/AC:L/Au:N/C:P/I:P/A:P
    let vector = "AV:N/AC:L/Au:N/C:P/I:P/A:P";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    // Impact = 10.41 * (1 - (1-0.275)^3) = 6.443...
    // Exploitability = 20 * 1.0 * 0.71 * 0.704 = 10.0
    // Score = ((0.6*6.443) + (0.4*10.0) - 1.5) * 1.176 = 7.459... -> round to 7.5
    assert_eq!(calculated_score, 7.5);
}

#[test]
fn test_v2_zero_impact_score() {
    // AV:N/AC:L/Au:N/C:N/I:N/A:N
    let vector = "AV:N/AC:L/Au:N/C:N/I:N/A:N";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    // Impact = 10.41 * (1 - (1-0)^3) = 0.0
    // Exploitability = 20 * 1.0 * 0.71 * 0.704 = 10.0
    // Score = ((0.6*0.0) + (0.4*10.0) - 1.5) * 0 = 0 (since impact is 0, f_impact is 0, so score should be 0)
    assert_eq!(calculated_score, 0.0);
}

#[test]
fn test_v2_undefined_temporal_and_environmental_metrics() {
    // AV:N/AC:L/Au:N/C:C/I:C/A:C/E:ND/RL:ND/RC:ND/CDP:ND/TD:ND/CR:ND/IR:ND/AR:ND
    let vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:ND/RL:ND/RC:ND/CDP:ND/TD:ND/CR:ND/IR:ND/AR:ND";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    let calculated_temporal_score = cvss
        .calculated_temporal_score()
        .expect("Failed to calculate temporal score");
    let calculated_environmental_score = cvss
        .calculated_environmental_score()
        .expect("Failed to calculate environmental score");

    // With all temporal and environmental metrics set to NotDefined,
    // the temporal and environmental scores should be the same as the base score
    assert_eq!(calculated_score, 10.0);
    assert_eq!(calculated_temporal_score, 10.0);
    assert_eq!(calculated_environmental_score, 10.0);
}

#[test]
fn test_v2_missing_temporal_and_environmental_metrics() {
    // AV:N/AC:L/Au:N/C:C/I:C/A:C
    let vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    let calculated_temporal_score = cvss
        .calculated_temporal_score()
        .expect("Failed to calculate temporal score");
    let calculated_environmental_score = cvss
        .calculated_environmental_score()
        .expect("Failed to calculate environmental score");

    // With all temporal and environmental metrics missing, the metrics should default to NotDefined,
    // so the temporal and environmental scores should be the same as the base score
    assert_eq!(calculated_score, 10.0);
    assert_eq!(calculated_temporal_score, 10.0);
    assert_eq!(calculated_environmental_score, 10.0);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2002-0392](https://www.first.org/cvss/v2/guide#3-3-1-CVE-2002-0392)
#[test]
fn test_v2_real_cve_2002_0392() {
    let vector = "AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:H";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    let calculated_temporal_score = cvss
        .calculated_temporal_score()
        .expect("Failed to calculate temporal score");
    let calculated_environmental_score = cvss
        .calculated_environmental_score()
        .expect("Failed to calculate environmental score");

    assert_eq!(calculated_score, 7.8);
    assert_eq!(calculated_temporal_score, 6.4);
    assert_eq!(calculated_environmental_score, 9.2);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2003-0062](https://www.first.org/cvss/v2/guide#3-3-3-CVE-2003-0062)
#[test]
fn test_v2_real_cve_2003_0062() {
    let vector = "AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:M";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    let calculated_temporal_score = cvss
        .calculated_temporal_score()
        .expect("Failed to calculate temporal score");
    let calculated_environmental_score = cvss
        .calculated_environmental_score()
        .expect("Failed to calculate environmental score");

    assert_eq!(calculated_score, 6.2);
    assert_eq!(calculated_temporal_score, 4.9);
    assert_eq!(calculated_environmental_score, 7.5);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2003-0818](https://www.first.org/cvss/v2/guide#3-3-2-CVE-2003-0818)
#[test]
fn test_v2_real_cve_2003_0818() {
    let vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:M/IR:M/AR:L";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");
    let calculated_temporal_score = cvss
        .calculated_temporal_score()
        .expect("Failed to calculate temporal score");
    let calculated_environmental_score = cvss
        .calculated_environmental_score()
        .expect("Failed to calculate environmental score");

    assert_eq!(calculated_score, 10.0);
    assert_eq!(calculated_temporal_score, 8.3);
    assert_eq!(calculated_environmental_score, 9.0);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2013-1937](https://www.first.org/cvss/v3.0/examples#phpMyAdmin-Reflected-Cross-site-Scripting-Vulnerability-CVE-2013-1937)
///
/// The same vector was also defined for:
/// [first.org CVE-2013-0375](https://www.first.org/cvss/v3.0/examples#MySQL-Stored-SQL-Injection-CVE-2013-0375)
#[test]
fn test_v2_real_cve_2013_1937() {
    let vector = "AV:N/AC:L/Au:S/C:P/I:P/A:N";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 5.5);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2014-3566](https://www.first.org/cvss/v3.0/examples#SSLv3-POODLE-Vulnerability-CVE-2014-3566)
#[test]
fn test_v2_real_cve_2014_3566() {
    let vector = "AV:N/AC:M/Au:N/C:P/I:N/A:N";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 4.3);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2012-1516](https://www.first.org/cvss/v3.0/examples#VMware-Guest-to-Host-Escape-Vulnerability-CVE-2012-1516)
#[test]
fn test_v2_real_cve_2012_1516() {
    let vector = "AV:N/AC:L/Au:S/C:C/I:C/A:C";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 9.0);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2009-0783](https://www.first.org/cvss/v3.0/examples#Apache-Tomcat-XML-Parser-Vulnerability-CVE-2009-0783)
///
/// The same vector was also defined for:
/// [first.org CVE-2018-3652](https://www.first.org/cvss/v3.1/examples#Intel-DCI-Issue-CVE-2018-3652)
#[test]
fn test_v2_real_cve_2009_0783() {
    let vector = "AV:L/AC:L/Au:N/C:P/I:P/A:P";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 4.6);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2012-0384](https://www.first.org/cvss/v3.0/examples#Cisco-IOS-Arbitrary-Command-Execution-Vulnerability-CVE-2012-0384)
#[test]
fn test_v2_real_cve_2012_0384() {
    let vector = "AV:N/AC:M/Au:S/C:C/I:C/A:C";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 8.5);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2015-1098](https://www.first.org/cvss/v3.0/examples#Apple-iWork-Denial-of-Service-Vulnerability-CVE-2015-1098)
///
/// The same vector was also defined for:
/// [first.org CVE-2015-0970](https://www.first.org/cvss/v3.0/examples#SearchBlox-Cross-Site-Request-Forgery-Vulnerability-CVE-2015-0970)
/// [first.org CVE-2014-0224](https://www.first.org/cvss/v3.0/examples#SSL-TLS-MITM-Vulnerability-CVE-2014-0224)
/// [first.org CVE-2016-2118](https://www.first.org/cvss/v3.0/examples#SAMR-LSAD-Privilege-Escalation-via-Protocol-Downgrade-Vulnerability-Badlock-CVE-2016-0128-and-CVE-2016-2118)
#[test]
fn test_v2_real_cve_2015_1098() {
    let vector = "AV:N/AC:M/Au:N/C:P/I:P/A:P";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 6.8);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2014-0160](https://www.first.org/cvss/v3.0/examples#OpenSSL-Heartbleed-Vulnerability-CVE-2014-0160)
///
/// The same vector was also defined for:
/// [first.org CVE-2010-0467](https://www.first.org/cvss/v3.0/examples#Joomla-Directory-Traversal-Vulnerability-CVE-2010-0467)
#[test]
fn test_v2_real_cve_2014_0160() {
    let vector = "AV:N/AC:L/Au:N/C:P/I:N/A:N";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 5.0);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2014-6271](https://www.first.org/cvss/v3.0/examples#GNU-Bourne-Again-Shell-Bash-Shellshock-Vulnerability-CVE-2014-6271)
///
/// The same vector was also defined for:
/// [first.org CVE-2012-5376](https://www.first.org/cvss/v3.0/examples#Google-Chrome-Sandbox-Bypass-vulnerability-CVE-2012-5376)
#[test]
fn test_v2_real_cve_2014_6271() {
    let vector = "AV:N/AC:L/Au:N/C:C/I:C/A:C";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 10.0);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2008-1447](https://www.first.org/cvss/v3.0/examples#DNS-Kaminsky-Bug-CVE-2008-1447)
///
/// The same vector was also defined for:
/// [first.org CVE-2012-1342](https://www.first.org/cvss/v3.0/examples#Cisco-Access-Control-Bypass-Vulnerability-CVE-2012-1342)
#[test]
fn test_v2_real_cve_2008_1447() {
    let vector = "AV:N/AC:L/Au:N/C:N/I:P/A:N";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 5.0);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2014-2005](https://www.first.org/cvss/v3.0/examples#Sophos-Login-Screen-Bypass-Vulnerability-CVE-2014-2005)
///
/// The same vector was also defined for:
/// [first.org CVE-2018-18913](https://www.first.org/cvss/v3.1/examples#Opera-DLL-search-order-hijacking-CVE-2018-18913)
#[test]
fn test_v2_real_cve_2014_2005() {
    let vector = "AV:L/AC:M/Au:N/C:C/I:C/A:C";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 6.9);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2013-6014](https://www.first.org/cvss/v3.0/examples#Juniper-Proxy-ARP-Denial-of-Service-Vulnerability-CVE-2013-6014)
#[test]
fn test_v2_real_cve_2013_6014() {
    let vector = "AV:A/AC:L/Au:N/C:N/I:C/A:N";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 6.1);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2014-9253](https://www.first.org/cvss/v3.0/examples#DokuWiki-Reflected-Cross-site-Scripting-Attack-CVE-2014-9253)
///
/// The same vector was also defined for:
/// [first.org CVE-2017-5942](https://www.first.org/cvss/v3.1/examples#WordPress-Mail-Plugin-Reflected-Cross-site-Scripting-Vulnerability-CVE-2017-5942)
#[test]
fn test_v2_real_cve_2014_9253() {
    let vector = "AV:N/AC:M/Au:N/C:N/I:P/A:N";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 4.3);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2009-0658](https://www.first.org/cvss/v3.0/examples#Adobe-Acrobat-Buffer-Overflow-Vulnerability-CVE-2009-0658)
///
/// The same vector was also defined for:
/// [first.org CVE-2016-1645](https://www.first.org/cvss/v3.0/examples#Google-Chrome-PDFium-JPEG-2000-Remote-Code-Execution-Vulnerability-CVE-2016-1645)
#[test]
fn test_v2_real_cve_2009_0658() {
    let vector = "AV:N/AC:M/Au:N/C:C/I:C/A:C";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 9.3);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2011-1265](https://www.first.org/cvss/v3.0/examples#Microsoft-Windows-Bluetooth-Remote-Code-Execution-Vulnerability-CVE-2011-1265)
#[test]
fn test_v2_real_cve_2011_1265() {
    let vector = "AV:A/AC:L/Au:N/C:C/I:C/A:C";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 8.3);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2014-2019](https://www.first.org/cvss/v3.0/examples#Apple-iOS-Security-Control-Bypass-Vulnerability-CVE-2014-2019)
#[test]
fn test_v2_real_cve_2014_2019() {
    let vector = "AV:L/AC:L/Au:N/C:N/I:C/A:N";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 4.9);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2016-0128](https://www.first.org/cvss/v3.0/examples#SAMR-LSAD-Privilege-Escalation-via-Protocol-Downgrade-Vulnerability-Badlock-CVE-2016-0128-and-CVE-2016-2118)
#[test]
fn test_v2_real_cve_2016_0128() {
    let vector = "AV:N/AC:M/Au:N/C:P/I:P/A:N";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 5.8);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2019-7551](https://www.first.org/cvss/v3.1/examples#Cantemo-Portal-Stored-Cross-site-Scripting-Vulnerability-CVE-2019-7551)
#[test]
fn test_v2_real_cve_2019_7551() {
    let vector = "AV:N/AC:M/Au:S/C:P/I:P/A:P";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 6.0);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2016-5558](https://www.first.org/cvss/v3.1/examples#Remote-Code-Execution-in-Oracle-Outside-in-Technology-CVE-2016-5558)
#[test]
fn test_v2_real_cve_2016_5558() {
    let vector = "AV:N/AC:L/Au:N/C:P/I:P/A:P";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 7.5);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2016-5729](https://www.first.org/cvss/v3.1/examples#Lenovo-ThinkPwn-Exploit-CVE-2016-5729)
#[test]
fn test_v2_real_cve_2016_5729() {
    let vector = "AV:L/AC:L/Au:S/C:C/I:C/A:C";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 6.8);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2015-2890](https://www.first.org/cvss/v3.1/examples#Failure-to-Lock-Flash-on-Resume-from-sleep-CVE-2015-2890)
#[test]
fn test_v2_real_cve_2015_2890() {
    let vector = "AV:L/AC:L/Au:N/C:C/I:C/A:C";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 7.2);
}

/// This is a real CVE with the metrics taken from the official first.org CVSS Scoring Guide examples:
/// [first.org CVE-2019-0884](https://www.first.org/cvss/v3.1/examples#Scripting-Engine-Memory-Corruption-Vulnerability-CVE-2019-0884)
#[test]
fn test_v2_real_cve_2019_0884() {
    let vector = "AV:N/AC:H/Au:N/C:C/I:C/A:C";
    let cvss = CvssV2::from_str(vector).expect("Failed to parse CVSS v2.0 vector");

    let calculated_score = cvss
        .calculated_base_score()
        .expect("Failed to calculate score");

    assert_eq!(calculated_score, 7.6);
}
