rule mysqlfast {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file mysqlfast.exe"
    family = "None"
    hacker = "None"
    hash = "32b60350390fe7024af7b4b8fbf50f13306c546f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "Invalid password hash: %s" fullword ascii
    $s3 = "-= MySql Hash Cracker =- " fullword ascii
    $s4 = "Usage: %s hash" fullword ascii
    $s5 = "Hash: %08lx%08lx" fullword ascii
    $s6 = "Found pass: " fullword ascii
    $s7 = "Pass not found" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 900KB and 4 of them
}