rule mimikatz_kirbi_ticket {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "KiRBi ticket for mimikatz"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $asn1 = { 76 82 ?? ?? 30 82 ?? ?? a0 03 02 01 05 a1 03 02 01 16 }
    $asn1_84 = { 76 84 ?? ?? ?? ?? 30 84 ?? ?? ?? ?? a0 84 00 00 00 03 02 01 05 a1 84 00 00 00 03 02 01 16 }
  condition:
    $asn1 at 0 or $asn1_84 at 0
}