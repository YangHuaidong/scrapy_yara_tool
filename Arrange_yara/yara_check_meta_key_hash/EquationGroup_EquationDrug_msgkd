rule EquationGroup_EquationDrug_msgkd {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file msgkd.ex_"
    family = "None"
    hacker = "None"
    hash1 = "25eec68fc9f0d8d1b5d72c9eae7bee29035918e9dcbeab13e276dec4b2ad2a56"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "KEysud" fullword ascii
    $s2 = "XWWWPWS" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}