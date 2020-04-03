rule APT_HiddenCobra_GhostSecret_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-08-11"
    description = "Detects Hidden Cobra Sample"
    family = "None"
    hacker = "None"
    hash1 = "45e68dce0f75353c448865b9abafbef5d4ed6492cd7058f65bf6aac182a9176a"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "ping 127.0.0.1 -n 3" fullword wide
    $s2 = "Process32" fullword ascii
    $s11 = "%2d%2d%2d%2d%2d%2d" fullword ascii
    $s12 = "del /a \"" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 400KB and all of them
}