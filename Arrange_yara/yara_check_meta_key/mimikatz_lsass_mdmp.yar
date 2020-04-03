rule mimikatz_lsass_mdmp {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "LSASS minidump file for mimikatz"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $lsass = "System32\\lsass.exe"   wide nocase
  condition:
    (uint32(0) == 0x504d444d) and $lsass and filesize > 50000KB and not filename matches /WER/
}