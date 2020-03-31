rule mimikatz_lsass_mdmp
{
   meta:
      description      = "LSASS minidump file for mimikatz"
      author         = "Benjamin DELPY (gentilkiwi)"
   strings:
      $lsass         = "System32\\lsass.exe"   wide nocase
   condition:
      (uint32(0) == 0x504d444d) and $lsass and filesize > 50000KB and not filename matches /WER/
}