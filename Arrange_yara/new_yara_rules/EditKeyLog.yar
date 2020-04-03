rule EditKeyLog {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file EditKeyLog.exe"
    family = "None"
    hacker = "None"
    hash = "a450c31f13c23426b24624f53873e4fc3777dc6b"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Press Any Ke" fullword ascii
    $s2 = "Enter 1 O" fullword ascii
    $s3 = "Bon >0 & <65535L" fullword ascii
    $s4 = "--Choose " fullword ascii
  condition:
    all of them
}