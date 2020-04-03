rule Cloaked_as_JPG {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-02-28"
    description = "Detects a cloaked file as JPG"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    score = 40
    threatname = "None"
    threattype = "None"
  strings:
    $fp1 = "<!DOCTYPE" ascii
  condition:
    uint16be(0x00) != 0xFFD8 and
    extension == ".jpg" and
    not uint32be(0) == 0x4749463839 and /* GIF Header */
    /* and
    not filepath contains "ASP.NET" */
    not $fp1 in (0..30) and
    not uint32be(0) == 0x89504E47 and /* PNG Header */
    not uint16be(0) == 0x8b1f /* GZIP */
}