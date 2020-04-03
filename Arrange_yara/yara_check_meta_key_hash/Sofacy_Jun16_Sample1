rule Sofacy_Jun16_Sample1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-06-14"
    description = "Detects Sofacy Malware mentioned in PaloAltoNetworks APT report"
    family = "None"
    hacker = "None"
    hash1 = "be1cfa10fcf2668ae01b98579b345ebe87dab77b6b1581c368d1aba9fd2f10a0"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/mzAa97"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "clconfg.dll" fullword ascii
    $s2 = "ASijnoKGszdpodPPiaoaghj8127391" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($s*) ) ) or ( all of them )
}