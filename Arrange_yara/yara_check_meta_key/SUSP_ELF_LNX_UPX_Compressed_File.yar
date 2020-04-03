rule SUSP_ELF_LNX_UPX_Compressed_File {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-12-12"
    description = "Detects a suspicious ELF binary with UPX compression"
    family = "None"
    hacker = "None"
    hash1 = "038ff8b2fef16f8ee9d70e6c219c5f380afe1a21761791e8cbda21fa4d09fdb4"
    judge = "black"
    reference = "Internal Research"
    score = 40
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii
    $s2 = "$Id: UPX" fullword ascii
    $s3 = "$Info: This file is packed with the UPX executable packer" ascii
    $fp1 = "check your UCL installation !"
  condition:
    uint16(0) == 0x457f and filesize < 2000KB and
    filesize > 30KB and 2 of ($s*)
    and not 1 of ($fp*)
}