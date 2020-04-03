rule BronzeButler_UACBypass_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-10-14"
    description = "Detects malware / hacktool sample from Bronze Butler incident"
    family = "None"
    hacker = "None"
    hash1 = "fe06b99a0287e2b2d9f7faffbda3a4b328ecc05eab56a3e730cfc99de803b192"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "\\Release\\BypassUacDll.pdb" ascii
    $x2 = "%programfiles%internet exploreriexplore.exe" fullword wide
    $x3 = "Elevation:Administrator!new:{3ad055" fullword wide
    $x4 = "BypassUac.pdb" fullword ascii
    $x5 = "[bypassUAC] started X64" fullword wide
    $x6 = "[bypassUAC] started X86" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them )
}