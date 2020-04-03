rule WiltedTulip_Tools_back {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-07-23"
    description = "Detects Chrome password dumper used in Operation Wilted Tulip"
    family = "None"
    hacker = "None"
    hash1 = "b7faeaa6163e05ad33b310a8fdc696ccf1660c425fa2a962c3909eada5f2c265"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://www.clearskysec.com/tulip"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "%s.exe -f \"C:\\Users\\Admin\\Google\\Chrome\\TestProfile\" -o \"c:\\passlist.txt\"" fullword ascii
    $x2 = "\\ChromePasswordDump\\Release\\FireMaster.pdb" fullword ascii
    $x3 = "//Dump Chrome Passwords to a Output file \"c:\\passlist.txt\"" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them )
}