rule Methodology_Suspicious_Shortcut_IconRemote_SMBorLocal
{
  meta:
    author = "@itsreallynick (Nick Carr)"
    description = "This is the syntax used for NTLM hash stealing via Responder - https://www.securify.nl/nl/blog/SFY20180501/living-off-the-land_-stealing-netntlm-hashes.html"
    reference = "https://twitter.com/ItsReallyNick/status/1176241449148588032"
    score = 50
    date = "27.09.2019"
  strings:
    $icon = "IconFile=file://" nocase
    $url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
    $url_explicit = "[InternetShortcut]" nocase
  condition:
    $icon and any of ($url*)
    and uint16(0) != 0x5A4D and uint32(0) != 0x464c457f and uint32(0) != 0xBEBAFECA and uint32(0) != 0xFEEDFACE and uint32(0) != 0xFEEDFACF and uint32(0) != 0xCEFAEDFE
    and filesize < 30KB
}