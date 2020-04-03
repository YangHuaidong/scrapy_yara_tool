rule EquationGroup_Toolset_Apr17_st_lp {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "3b6f756cca096548dcad2b6c241c1dafd16806c060bec82a530f4d38755286a2"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Previous command: set injection processes (status=0x%x)" fullword ascii
    $x2 = "Secondary injection process is <null> [no secondary process will be used]" fullword ascii
    $x3 = "Enter the address to be used as the spoofed IP source address (xxx.xxx.xxx.xxx) -> " fullword ascii
    $x4 = "E: Execute a Command on the Implant" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}