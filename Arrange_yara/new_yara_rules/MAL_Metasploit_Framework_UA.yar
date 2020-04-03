rule MAL_Metasploit_Framework_UA {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-08-16"
    description = "Detects User Agent used in Metasploit Framework"
    family = "None"
    hacker = "None"
    hash1 = "1743e1bd4176ffb62a1a0503a0d76033752f8bd34f6f09db85c2979c04bbdd29"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/rapid7/metasploit-framework/commit/12a6d67be48527f5d3987e40cac2a0cbb4ab6ce7"
    score = 65
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 400KB and 1 of them
}