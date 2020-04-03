rule IMPLANT_12_v1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-10"
    description = "Cosmic Duke Implant by APT29"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $FUNC = {A1 [3-5] 33 C5 89 [2-3] 56 57 83 [4-6] 64}
  condition:
    (uint16(0) == 0x5A4D) and $FUNC
}