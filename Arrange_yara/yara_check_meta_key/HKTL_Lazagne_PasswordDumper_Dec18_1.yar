rule HKTL_Lazagne_PasswordDumper_Dec18_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-12-11"
    description = "Detects password dumper Lazagne often used by middle eastern threat groups"
    family = "None"
    hacker = "None"
    hash1 = "1205f5845035e3ee30f5a1ced5500d8345246ef4900bcb4ba67ef72c0f79966c"
    hash2 = "884e991d2066163e02472ea82d89b64e252537b28c58ad57d9d648b969de6a63"
    hash3 = "bf8f30031769aa880cdbe22bc0be32691d9f7913af75a5b68f8426d4f0c7be50"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "softwares.opera(" fullword ascii
    $s2 = "softwares.mozilla(" fullword ascii
    $s3 = "config.dico(" fullword ascii
    $s4 = "softwares.chrome(" fullword ascii
    $s5 = "softwares.outlook(" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 17000KB and 1 of them
}