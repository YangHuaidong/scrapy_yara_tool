rule IMPLANT_6_v7 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-10"
    description = "Sednit / EVILTOSS Implant by APT28"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $STR1 = "Init1"
    $OPT1 = "ServiceMain"
    $OPT2 = "netids" nocase wide ascii
    $OPT3 = "netui" nocase wide ascii
    $OPT4 = "svchost.exe" wide ascii
    $OPT5 = "network" nocase wide ascii
  condition:
    (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
    uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and $STR1 and 2 of ($OPT*)
}