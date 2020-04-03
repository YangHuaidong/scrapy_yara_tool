rule WINDOWS_UPDATE_BDC {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "None"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  condition:
    (uint32be(0) == 0x44434d01 and // magic: DCM PA30
    uint32be(4) == 0x50413330)
    or
    (uint32be(0) == 0x44434401 and
    uint32be(12)== 0x50413330)    // magic: DCD PA30
}