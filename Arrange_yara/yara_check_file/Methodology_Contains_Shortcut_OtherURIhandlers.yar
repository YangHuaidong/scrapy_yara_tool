rule Methodology_Contains_Shortcut_OtherURIhandlers
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "Noisy rule for .URL shortcuts containing unique URI handlers"
    description = "Detects possible shortcut usage for .URL persistence"
    reference = "https://twitter.com/cglyer/status/1176184798248919044"
    score = 35
    date = "27.09.2019"
  strings:
    $file = "URL="
    $filenegate = /[\x0a\x0d](Base|)URL\s*=\s*(https?|file):\/\// nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $file and any of ($url*) and not $filenegate
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}