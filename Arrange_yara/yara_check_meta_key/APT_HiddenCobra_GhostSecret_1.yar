rule APT_HiddenCobra_GhostSecret_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-08-11"
    description = "Detects Hidden Cobra Sample"
    family = "None"
    hacker = "None"
    hash1 = "05a567fe3f7c22a0ef78cc39dcf2d9ff283580c82bdbe880af9549e7014becfc"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "%s\\%s.dll" fullword wide
    $s2 = "PROXY_SVC_DLL.dll" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}