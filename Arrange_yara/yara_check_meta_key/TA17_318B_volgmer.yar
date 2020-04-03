rule TA17_318B_volgmer {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-11-15"
    description = "Malformed User Agent in Volgmer malware"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/alerts/TA17-318B"
    threatname = "None"
    threattype = "None"
  strings:
    $s = "Mozillar/"
  condition:
    ( uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550 ) and $s
}