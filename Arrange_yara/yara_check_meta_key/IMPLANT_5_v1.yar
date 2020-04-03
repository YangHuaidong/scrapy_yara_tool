rule IMPLANT_5_v1 {
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
    $hexstr = {2D 00 53 00 69 00 00 00 2D 00 53 00 70 00 00 00 2D 00 55 00
    70 00 00 00 2D 00 50 00 69 00 00 00 2D 00 50 00 70 00 00 00}
    $UDPMSG1 = "error 2005 recv from server UDP - %d\x0a"
    $TPSMSG1 = "error 2004 send to TPS - %d\x0a"
    $TPSMSG2 = "error 2003 recv from TPS - %d\x0a"
    $UDPMSG2 = "error 2002 send to server UDP - %d\x0a"
  condition:
    any of them
}