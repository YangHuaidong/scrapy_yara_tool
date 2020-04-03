rule SLServer_unknown_string {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016/04/18"
    description = "Searches for a unique string."
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    score = 75
    threatname = "None"
    threattype = "None"
  strings:
    $string = "test-b7fa835a39"
  condition:
    uint16(0) == 0x5A4D and
    uint32(uint32(0x3C)) == 0x00004550 and
    $string
}