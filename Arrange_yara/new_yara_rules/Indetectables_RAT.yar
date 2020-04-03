rule Indetectables_RAT {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-10-01"
    description = "Detects Indetectables RAT based on strings found in research by Paul Rascagneres & Ronan Mouchoux"
    family = "None"
    hacker = "None"
    hash1 = "081905074c19d5e32fd41a24b4c512d8fd9d2c3a8b7382009e3ab920728c7105"
    hash2 = "66306c2a55a3c17b350afaba76db7e91bfc835c0e90a42aa4cf59e4179b80229"
    hash3 = "1fa810018f6dd169e46a62a4f77ae076f93a853bfc33c7cf96266772535f6801"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://www.sekoia.fr/blog/when-a-brazilian-string-smells-bad/"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Coded By M3" fullword wide
    $s2 = "Stub Undetector M3" fullword wide
    $s3 = "www.webmenegatti.com.br" wide
    $s4 = "M3n3gatt1" fullword wide
    $s5 = "TheMisterFUD" fullword wide
    $s6 = "KillZoneKillZoneKill" fullword ascii
    $s7 = "[[__M3_F_U_D_M3__]]$" fullword ascii
    $s8 = "M3_F_U_D_M3" ascii
    $s9 = "M3n3gatt1hack3r" fullword wide
    $s10 = "M3n3gatt1hack3r" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 5000KB and 1 of them
}