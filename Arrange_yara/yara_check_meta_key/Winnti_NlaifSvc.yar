rule Winnti_NlaifSvc {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-25"
    description = "Winnti sample - file NlaifSvc.dll"
    family = "None"
    hacker = "None"
    hash1 = "964f9bfd52b5a93179b90d21705cd0c31461f54d51c56d558806fe0efff264e5"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/VbvJtL"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "cracked by ximo" ascii
    $s1 = "Yqrfpk" fullword ascii
    $s2 = "IVVTOC" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 900KB and ( 1 of ($x*) or 2 of them ) ) or ( 3 of them )
}