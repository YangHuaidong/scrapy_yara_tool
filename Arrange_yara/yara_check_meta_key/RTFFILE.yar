rule RTFFILE {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Detects RTF files"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  condition:
    uint32be(0) == 0x7B5C7274
}