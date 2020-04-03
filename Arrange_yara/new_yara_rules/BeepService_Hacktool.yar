rule BeepService_Hacktool {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-05-12"
    description = "Detects BeepService Hacktool used by Chinese APT groups"
    family = "None"
    hacker = "None"
    hash1 = "032df812a68852b6f3822b9eac4435e531ca85bdaf3ee99c669134bd16e72820"
    hash2 = "e30933fcfc9c2a7443ee2f23a3df837ca97ea5653da78f782e2884e5a7b734f7"
    hash3 = "ebb9c4f7058e19b006450b8162910598be90428998df149977669e61a0b7b9ed"
    hash4 = "6db2ffe7ec365058f9d3b48dcca509507c138f19ade1adb5f13cf43ea0623813"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/p32Ozf"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "\\\\%s\\admin$\\system32\\%s" fullword ascii
    $s1 = "123.exe" fullword ascii
    $s2 = "regclean.exe" fullword ascii
    $s3 = "192.168.88.69" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and $x1 and 1 of ($s*)
}