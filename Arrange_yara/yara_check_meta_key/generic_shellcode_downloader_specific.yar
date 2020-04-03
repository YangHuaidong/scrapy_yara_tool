rule generic_shellcode_downloader_specific {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018/04/06"
    description = "Detects Doorshell from NCSC report"
    family = "None"
    hacker = "None"
    hash = "b8bc0611a7fd321d2483a0a9a505251e15c22402e0cfdc62c0258af53ed3658a"
    judge = "black"
    reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
    threatname = "None"
    threattype = "None"
  strings:
    $push1 = { 68 6c 6c 6f 63 }
    $push2 = { 68 75 61 6c 41 }
    $push3 = { 68 56 69 72 74 }
    $a = { ba 90 02 00 00 46 c1 c6 19 03 dd 2b f4 33 de }
    $b = { 87 c0 81 f2 d1 19 89 14 c1 c8 1f ff e0 }
  condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3C)) == 0x4550) and ($a or $b) and @push1 < @push2 and @push2 < @push3
}