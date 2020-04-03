rule EquationGroup_Toolset_Apr17_EXPA {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "2017176d3b5731a188eca1b71c50fb938c19d6260c9ff58c7c9534e317d315f8"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "* The target is IIS 6.0 but is not running content indexing servicess," fullword ascii
    $x2 = "--ver 6 --sp <service_pack> --lang <language> --attack shellcode_option[s]sL" fullword ascii
    $x3 = "By default, the shellcode will attempt to immediately connect s$" fullword ascii
    $x4 = "UNEXPECTED SHELLCODE CONFIGURATION ERRORs" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 12000KB and 1 of them )
}