rule PUP_ComputraceAgent {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-05-01"
    description = "Absolute Computrace Agent Executable"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://asert.arbornetworks.com/lojack-becomes-a-double-agent/"
    threatname = "None"
    threattype = "None"
  strings:
    $a = { d1 e0 f5 8b 4d 0c 83 d1 00 8b ec ff 33 83 c3 04 }
    $b1 = { 72 70 63 6e 65 74 70 2e 65 78 65 00 72 70 63 6e 65 74 70 00 }
    $b2 = { 54 61 67 49 64 00 }
  condition:
    uint16(0) == 0x5a4d and filesize < 40KB and ($a or ($b1 and $b2))
}