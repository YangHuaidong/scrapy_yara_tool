rule IMPLANT_1_v3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-10"
    description = "Downrage Implant by APT28"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $rol7encode = { 0f b7 c9 c1 c0 07 83 c2 02 33 c1 0f b7 0a 47 66 85 c9 75 }
  condition:
    (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
    uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}