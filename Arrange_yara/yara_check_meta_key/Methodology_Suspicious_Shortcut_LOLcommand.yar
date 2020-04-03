rule Methodology_Suspicious_Shortcut_LOLcommand {
  meta:
    author = "Spider"
    comment = "None"
    date = "27.09.2019"
    description = "Detects possible shortcut usage for .URL persistence"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://twitter.com/ItsReallyNick/status/1176601500069576704"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $file1 = /[\x0a\x0d](IconFile|(Base|)URL)\s*=[^\x0d]*(powershell|cmd|certutil|mshta|wscript|cscript|rundll32|wmic|regsvr32|msbuild)(\.exe|)[^\x0d]{2,}\x0d/ nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    any of ($url*) and any of ($file*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}