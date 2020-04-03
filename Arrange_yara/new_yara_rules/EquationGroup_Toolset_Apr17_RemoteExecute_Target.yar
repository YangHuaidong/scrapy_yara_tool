rule EquationGroup_Toolset_Apr17_RemoteExecute_Target {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "4a649ca8da7b5499821a768c650a397216cdc95d826862bf30fcc4725ce8587f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Win32_Process" fullword ascii
    $s2 = "\\\\%ls\\root\\cimv2" fullword wide
    $op1 = { 83 7b 18 01 75 12 83 63 }
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}