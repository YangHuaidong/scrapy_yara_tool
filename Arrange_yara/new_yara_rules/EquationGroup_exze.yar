rule EquationGroup_exze {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- file exze"
    family = "None"
    hacker = "None"
    hash1 = "1af6dde6d956db26c8072bf5ff26759f1a7fa792dd1c3498ba1af06426664876"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "shellFile" fullword ascii
    $s2 = "completed.1" fullword ascii
    $s3 = "zeke_remove" fullword ascii
  condition:
    ( uint16(0) == 0x457f and filesize < 80KB and all of them )
}