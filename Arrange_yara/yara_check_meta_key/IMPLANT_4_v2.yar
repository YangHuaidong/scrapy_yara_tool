rule IMPLANT_4_v2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-10"
    description = "BlackEnergy / Voodoo Bear Implant by APT28"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $BUILD_USER32 = {75 73 65 72 ?? ?? ?? 33 32 2E 64}
    $BUILD_ADVAPI32 = {61 64 76 61 ?? ?? ?? 70 69 33 32}
    $CONSTANT = { 26 80 ac c8 }
  condition:
    (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
    uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}