rule Methodology_Suspicious_Shortcut_WebDAV {
  meta:
    author = "Spider"
    comment = "None"
    date = "27.09.2019"
    description = "Detects possible shortcut usage for .URL persistence"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://twitter.com/cglyer/status/1176243536754282497"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $file1 = /[\x0a\x0d](IconFile|(Base|)URL)\s*=\s*\/\/[A-Za-z0-9]/
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    any of ($url*) and any of ($file*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}