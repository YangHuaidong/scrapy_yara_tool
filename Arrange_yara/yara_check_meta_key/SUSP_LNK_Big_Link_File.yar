rule SUSP_LNK_Big_Link_File {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-05-15"
    description = "Detects a suspiciously big LNK file - maybe with embedded content"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "Internal Research"
    score = 65
    threatname = "None"
    threattype = "None"
  condition:
    uint16(0) == 0x004c and uint32(4) == 0x00021401 and filesize > 200KB
}