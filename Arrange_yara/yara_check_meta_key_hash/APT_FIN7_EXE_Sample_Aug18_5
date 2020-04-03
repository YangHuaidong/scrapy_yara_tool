rule APT_FIN7_EXE_Sample_Aug18_5 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-08-01"
    description = "Detects sample from FIN7 report in August 2018"
    family = "None"
    hacker = "None"
    hash1 = "7789a3d7d05c30b4efaf3f2f5811804daa56d78a9a660968a4f1f9a78a9108a0"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "x0=%d, y0=%d, x1=%d, y1=%d" fullword ascii
    $s3 = "sdfkjdfjfhgurgvncmnvmfdjdkfjdkfjdf" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 400KB and all of them
}