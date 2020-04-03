rule IMPLANT_4_v12 {
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
    $CMP1 = {81 ?? 4D 5A 00 00 }
    $SUB1 = {81 ?? 00 10 00 00}
    $CMP2 = { 66 81 38 4d 5a }
    $SUB2 = { 2d 00 10 00 00 }
    $HAL = "HAL.dll"
    $OUT = {E6 64 E9 ?? ?? FF FF}
  condition:
    (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
    uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and ($CMP1 or $CMP2)
    and ($SUB1 or $SUB2) and $OUT and $HAL
}