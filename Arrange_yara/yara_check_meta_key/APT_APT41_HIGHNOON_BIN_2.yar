rule APT_APT41_HIGHNOON_BIN_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-08-07"
    description = "Detects APT41 malware HIGHNOON.BIN"
    family = "None"
    hacker = "None"
    hash1 = "63e8ed9692810d562adb80f27bb1aeaf48849e468bf5fd157bc83ca83139b6d7"
    hash2 = "c51c5bbc6f59407286276ce07f0f7ea994e76216e0abe34cbf20f1b1cbd9446d"
    judge = "black"
    reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "\\Double\\Door_wh\\" ascii
    $x2 = "[Stone] Config --> 2k3 TCP Positive Logout." fullword ascii
    $x3 = "\\RbDoorX64.pdb" ascii
    $x4 = "RbDoor, Version 1.0" fullword wide
    $x5 = "About RbDoor" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}