rule HiddenCobra_r4_wiper_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-12-12"
    description = "Detects HiddenCobra Wiper"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/sites/default/files/publications/MAR-10135536.11.WHITE.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $PhysicalDriveSTR = "\\\\.\\PhysicalDrive" wide
    $ExtendedWrite = { b4 43 b0 00 cd 13 }
  condition:
    uint16(0) == 0x5a4d and uint16(uint32(0x3c)) == 0x4550 and all of them
}