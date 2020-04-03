rule APT_MAL_HOPLIGHT_NK_HiddenCobra_Apr19_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-04-13"
    description = "Detects HOPLIGHT malware used by HiddenCobra APT group"
    family = "None"
    hacker = "None"
    hash1 = "d77fdabe17cdba62a8e728cbe6c740e2c2e541072501f77988674e07a05dfb39"
    judge = "unknown"
    reference = "https://www.us-cert.gov/ncas/analysis-reports/AR19-100A"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "www.naver.com" fullword ascii
    $s2 = "PolarSSL Test CA0" fullword ascii
  condition:
    filesize < 1000KB and all of them
}