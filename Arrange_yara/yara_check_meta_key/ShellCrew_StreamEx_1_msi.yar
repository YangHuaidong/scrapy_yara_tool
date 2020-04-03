rule ShellCrew_StreamEx_1_msi {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-10"
    description = "Auto-generated rule - file msi.dll"
    family = "None"
    hacker = "None"
    hash1 = "8c9048e2f5ea2ef9516cac06dc0fba8a7e97754468c0d9dc1e5f7bce6dbda2cc"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://blog.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "msi.dll.eng" fullword wide
    $s2 = "ahinovx" fullword ascii
    $s3 = "jkpsxy47CDEMNSTYbhinqrwx56" fullword ascii
    $s4 = "PVYdejmrsy12" fullword ascii
    $s6 = "FLMTUZaijkpsxy45CD" fullword ascii
    $s7 = "afhopqvw34ABIJOPTYZehmo" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 20KB and 3 of them )
}