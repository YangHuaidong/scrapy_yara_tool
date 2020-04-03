rule SLServer_campaign_code {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016/04/18"
    description = "Searches for the related campaign code."
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    score = 75
    threatname = "None"
    threattype = "None"
  strings:
    $campaign = "wthkdoc0106"
  condition:
    uint16(0) == 0x5A4D and
    uint32(uint32(0x3C)) == 0x00004550 and
    $campaign
}