rule IMPLANT_8_v2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-10"
    description = "HAMMERTOSS / HammerDuke Implant by APT29"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $DOTNET = "mscorlib" ascii
    $XOR = { 61 20 aa 00 00 00 61 }
  condition:
    (uint16(0) == 0x5A4D) and all of them
}