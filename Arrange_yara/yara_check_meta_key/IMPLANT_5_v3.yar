rule IMPLANT_5_v3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-10"
    description = "XTunnel Implant by APT28"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $BYTES1 = { 0F AF C0 6? C0 07 00 00 00 2D 01 00 00 00 0F AF ?? 39 ?8 }
    $BYTES2 = { 0F AF C0 6? C0 07 48 0F AF ?? 39 ?8 }
  condition:
    any of them
}