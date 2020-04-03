rule CN_Honker_safe3wvs_cgiscan {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file cgiscan.exe"
    family = "None"
    hacker = "None"
    hash = "f94bbf2034ad9afa43cca3e3a20f142e0bb54d75"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "httpclient.exe" fullword wide
    $s3 = "www.safe3.com.cn" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 357KB and all of them
}