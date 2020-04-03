rule Nautilus_modified_rc4_loop {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017/11/23"
    description = "Rule for detection of Nautilus based on assembly code for a modified RC4 loop"
    family = "None"
    hacker = "None"
    hash = "a415ab193f6cd832a0de4fcc48d5f53d6f0b06d5e13b3c359878c6c31f3e7ec3"
    judge = "black"
    reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
    threatname = "None"
    threattype = "None"
  strings:
    $a = { 42 0f b6 14 04 41 ff c0 03 d7 0f b6 ca 8a 14 0c 43 32 14 13 41 88 12 49 ff c2 49 ff c9 }
  condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $a
}