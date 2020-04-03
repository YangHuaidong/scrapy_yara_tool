rule APT_MAL_DNS_Hijacking_Campaign_AA19_024A {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-01-25"
    description = "Detects malware used in DNS Hijackign campaign"
    family = "None"
    hacker = "None"
    hash1 = "2010f38ef300be4349e7bc287e720b1ecec678cacbf0ea0556bcf765f6e073ec"
    hash2 = "45a9edb24d4174592c69d9d37a534a518fbe2a88d3817fc0cc739e455883b8ff"
    judge = "unknown"
    reference = "https://www.us-cert.gov/ncas/alerts/AA19-024A"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "/Client/Login?id=" fullword ascii
    $s3 = "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko" fullword ascii
    $s4 = ".\\Configure.txt" fullword ascii
    $s5 = "Content-Disposition: form-data; name=\"files\"; filename=\"" fullword ascii
    $s6 = "Content-Disposition: form-data; name=\"txts\"" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them
}