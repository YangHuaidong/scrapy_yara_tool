rule Sofacy_Jun16_Sample3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-06-14"
    description = "Detects Sofacy Malware mentioned in PaloAltoNetworks APT report"
    family = "None"
    hacker = "None"
    hash1 = "c2551c4e6521ac72982cb952503a2e6f016356e02ee31dea36c713141d4f3785"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/mzAa97"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "ASLIiasiuqpssuqkl713h" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and $s1
}