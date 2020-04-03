rule OilRig_Campaign_Reconnaissance {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-10-12"
    description = "Detects Windows discovery commands - known from OilRig Campaign"
    family = "None"
    hacker = "None"
    hash1 = "5893eae26df8e15c1e0fa763bf88a1ae79484cdb488ba2fc382700ff2cfab80c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/QMRZ8K"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "whoami & hostname & ipconfig /all" ascii
    $s2 = "net user /domain 2>&1 & net group /domain 2>&1" ascii
    $s3 = "net group \"domain admins\" /domain 2>&1 & " ascii
  condition:
    ( filesize < 1KB and 1 of them )
}