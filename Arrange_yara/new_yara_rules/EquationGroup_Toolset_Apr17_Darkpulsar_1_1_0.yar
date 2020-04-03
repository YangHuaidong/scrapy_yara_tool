rule EquationGroup_Toolset_Apr17_Darkpulsar_1_1_0 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "b439ed18262aec387984184e86bfdb31ca501172b1c066398f8c56d128ba855a"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "[%s] - Error upgraded DLL architecture does not match target architecture (0x%x)" fullword ascii
    $x2 = "[%s] - Error building DLL loading shellcode" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}