rule Waterbear_9_Jun17 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-06-23"
    description = "Detects malware from Operation Waterbear"
    family = "None"
    hacker = "None"
    hash1 = "fc74d2434d48b316c9368d3f90fea19d76a20c09847421d1469268a32f59664c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/L9g9eR"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "ADVPACK32.DLL" fullword wide
    $s2 = "ADVPACK32" fullword wide
    $a1 = "U2_Dll.dll" fullword ascii
    $b1 = "ProUpdate" fullword ascii
    $b2 = "Update.dll" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 30KB and all of ($s*) and ( $a1 or all of ($b*) )
}