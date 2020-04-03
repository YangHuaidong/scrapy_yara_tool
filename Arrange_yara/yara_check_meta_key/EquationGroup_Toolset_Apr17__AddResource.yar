rule EquationGroup_Toolset_Apr17__AddResource {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "e83e4648875d4c4aa8bc6f3c150c12bad45d066e2116087cdf78a4a4efbab6f0"
    hash2 = "5a04d65a61ef04f5a1cbc29398c767eada367459dc09c54c3f4e35015c71ccff"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "%s cm 10 2000 \"c:\\MY DIR\\myapp.exe\" c:\\MyResourceData.dat" fullword ascii
    $s2 = "<PE path> - the path to the PE binary to which to add the resource." fullword ascii
    $s3 = "Unable to get path for target binary." fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 300KB and 2 of them )
}