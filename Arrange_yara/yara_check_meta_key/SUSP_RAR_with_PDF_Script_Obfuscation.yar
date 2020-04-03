rule SUSP_RAR_with_PDF_Script_Obfuscation {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-04-06"
    description = "Detects RAR file with suspicious .pdf extension prefix to trick users"
    family = "None"
    hacker = "None"
    hash1 = "b629b46b009a1c2306178e289ad0a3d9689d4b45c3d16804599f23c90c6bca5b"
    judge = "black"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = ".pdf.vbe" ascii
    $s2 = ".pdf.vbs" ascii
    $s3 = ".pdf.ps1" ascii
    $s4 = ".pdf.bat" ascii
    $s5 = ".pdf.exe" ascii
  condition:
    uint32(0) == 0x21726152 and 1 of them
}