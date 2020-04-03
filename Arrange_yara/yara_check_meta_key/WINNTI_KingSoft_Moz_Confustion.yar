import "pe"
rule WINNTI_KingSoft_Moz_Confustion {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-04-13"
    description = "Detects Barium sample with Copyright confusion"
    family = "None"
    hacker = "None"
    hash1 = "070ee4a40852b26ec0cfd79e32176287a6b9d2b15e377281d8414550a83f6496"
    judge = "black"
    reference = "https://www.virustotal.com/en/file/070ee4a40852b26ec0cfd79e32176287a6b9d2b15e377281d8414550a83f6496/analysis/"
    threatname = "None"
    threattype = "None"
  condition:
    uint16(0) == 0x5a4d and filesize < 3000KB and (
    pe.imphash() == "7f01b23ccfd1017249c36bc1618d6892" or
    pe.version_info["LegalCopyright"] contains "Mozilla Corporation"
    and pe.version_info["ProductName"] contains "Kingsoft"
}