rule Nautilus_rc4_key {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017/11/23"
    description = "Rule for detection of Nautilus based on a hardcoded RC4 key"
    family = "None"
    hacker = "None"
    hash = "a415ab193f6cd832a0de4fcc48d5f53d6f0b06d5e13b3c359878c6c31f3e7ec3"
    judge = "black"
    reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
    threatname = "None"
    threattype = "None"
  strings:
    $key = { 31 42 31 34 34 30 44 39 30 46 43 39 42 43 42 34 36 41 39 41 43 39 36 34 33 38 46 45 45 41 38 42 }
  condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $key
}