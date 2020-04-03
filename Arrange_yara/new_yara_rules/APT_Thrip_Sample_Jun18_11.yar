import "pe"

rule APT_Thrip_Sample_Jun18_11 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-06-21"
    description = "Detects sample found in Thrip report by Symantec "
    family = "None"
    hacker = "None"
    hash1 = "590a6796b97469f8e6977832a63c0964464901f075a9651f7f1b4578e55bd8c8"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\AppData\\Local\\Temp\\dw20.EXE" ascii
    $s2 = "C:\\Windows\\system32\\sysprep\\cryptbase.dll" fullword ascii
    $s3 = "WFQNJMBWF" fullword ascii
    $s4 = "SQLWLWZSF" fullword ascii
    $s5 = "PFQUFQSBPP" fullword ascii
    $s6 = "WQZXQFPVOW" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB
    and ( pe.imphash() == "6eef4394490378f32d134ab3bf4bf194" or all of them )
}