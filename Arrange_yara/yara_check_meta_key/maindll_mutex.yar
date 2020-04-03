rule maindll_mutex {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016/04/18"
    description = "Matches on the maindll mutex"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    score = 75
    threatname = "None"
    threattype = "None"
  strings:
    $mutex = "h31415927tttt"
  condition:
    uint16(0) == 0x5A4D and
    uint32(uint32(0x3C)) == 0x00004550 and
    $mutex
}