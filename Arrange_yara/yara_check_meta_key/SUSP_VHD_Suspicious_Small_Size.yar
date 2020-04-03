rule SUSP_VHD_Suspicious_Small_Size {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-12-21"
    description = "Detects suspicious VHD files"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://twitter.com/MeltX0R/status/1208095892877774850"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    /* VHD */
    $hc1 = { 63 6f 6e 65 63 74 69 78 }
  condition:
    uint16(0) == 0x6f63 and $hc1 at 0 and
    filesize <= 4000KB
}