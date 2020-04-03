rule HKTL_SqlMap_backdoor {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-10-09"
    description = "Detects SqlMap backdoors"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://github.com/sqlmapproject/sqlmap"
    threatname = "None"
    threattype = "None"
  condition:
    ( uint32(0) == 0x8e859c07 or
    uint32(0) == 0x2d859c07 or
    uint32(0) == 0x92959c07 or
    uint32(0) == 0x929d9c07 or
    uint32(0) == 0x29959c07 or
    uint32(0) == 0x2b8d9c07 or
    uint32(0) == 0x2b859c07 or
    uint32(0) == 0x28b59c07 ) and filesize < 2KB
}