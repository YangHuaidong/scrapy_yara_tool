rule SAM_Hive_Backup {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/31"
    description = "Detects a SAM hive backup file"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\SystemRoot\\System32\\Config\\SAM" wide fullword
  condition:
    uint32(0) == 0x66676572 and $s1 in (0..100) and
    not filename contains "sam.log" and
    not filename contains "SAM.LOG" and
    not filename contains "_sam" and
    not filename == "SAM" and
    not filename == "sam"
}