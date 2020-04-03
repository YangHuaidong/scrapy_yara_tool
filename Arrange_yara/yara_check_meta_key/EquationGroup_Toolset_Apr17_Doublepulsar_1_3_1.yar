rule EquationGroup_Toolset_Apr17_Doublepulsar_1_3_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "15ffbb8d382cd2ff7b0bd4c87a7c0bffd1541c2fe86865af445123bc0b770d13"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "[+] Ping returned Target architecture: %s - XOR Key: 0x%08X" fullword ascii
    $x2 = "[.] Sending shellcode to inject DLL" fullword ascii
    $x3 = "[-] Error setting ShellcodeFile name" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}