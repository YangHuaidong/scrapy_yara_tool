rule SUSP_Office_Dropper_Strings {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-09-13"
    description = "Detects Office droppers that include a notice to enable active content"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $a1 = "_VBA_PROJECT" fullword wide
    $s1 = "click enable editing" fullword ascii
    $s2 = "click enable content" fullword ascii
    $s3 = "\"Enable Editing\"" fullword ascii
    $s4 = "\"Enable Content\"" fullword ascii
  condition:
    uint16(0) == 0xcfd0 and filesize < 500KB and $a1 and 1 of ($s*)
}