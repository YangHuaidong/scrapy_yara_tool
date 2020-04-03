rule Methodology_Suspicious_Shortcut_Evasion {
  meta:
    author = "Spider"
    comment = "None"
    date = "27.09.2019"
    description = "Non-standard .URLs and evasion"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://twitter.com/DissectMalware/status/1176736510856634368"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $URI = /[\x0a\x0d](IconFile|(Base|)URL)[^\x0d=]+/ nocase
    $filetype_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $filetype_explicit = "[InternetShortcut]" nocase
  condition:
    any of ($filetype*) and $URI //and $URInegate
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}