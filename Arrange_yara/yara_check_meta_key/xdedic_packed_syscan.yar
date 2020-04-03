rule xdedic_packed_syscan {
  meta:
    author = "Spider"
    comment = "None"
    company = "Kaspersky Lab"
    date = "None"
    description = "None"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $a1 = "SysScan.exe" nocase ascii wide
    $a2 = "1.3.4." wide
  condition:
    uint16(0) == 0x5A4D and filesize > 500KB and filesize < 1500KB and all of them
}