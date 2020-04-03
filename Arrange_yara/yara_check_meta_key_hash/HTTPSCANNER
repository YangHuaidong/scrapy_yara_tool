rule HTTPSCANNER {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file HTTPSCANNER.EXE"
    family = "None"
    hacker = "None"
    hash = "ae2929346944c1ea3411a4562e9d5e2f765d088a"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "HttpScanner.exe" fullword wide
    $s2 = "HttpScanner" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 3500KB and all of them
}