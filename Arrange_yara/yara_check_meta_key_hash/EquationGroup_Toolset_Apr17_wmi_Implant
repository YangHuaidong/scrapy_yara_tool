rule EquationGroup_Toolset_Apr17_wmi_Implant {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "de08d6c382faaae2b4b41b448b26d82d04a8f25375c712c12013cb0fac3bc704"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "SELECT ProcessId,Description,ExecutablePath FROM Win32_Process" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 50KB and all of them )
}