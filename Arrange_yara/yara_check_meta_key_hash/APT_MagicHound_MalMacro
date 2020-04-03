rule APT_MagicHound_MalMacro {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-17"
    description = "Detects malicious macro / powershell in Office document"
    family = "None"
    hacker = "None"
    hash1 = "66d24a529308d8ab7b27ddd43a6c2db84107b831257efb664044ec4437f9487b"
    hash2 = "e5b643cb6ec30d0d0b458e3f2800609f260a5f15c4ac66faf4ebf384f7976df6"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.secureworks.com/blog/iranian-pupyrat-bites-middle-eastern-organizations"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "powershell.exe " fullword ascii
    $s2 = "CommandButton1_Click" fullword ascii
    $s3 = "URLDownloadToFile" fullword ascii
  condition:
    ( uint16(0) == 0xcfd0 and filesize < 8000KB and all of them )
}