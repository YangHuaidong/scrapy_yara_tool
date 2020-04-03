rule Disclosed_0day_POCs_lpe_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-07-07"
    description = "Detects POC code from disclosed 0day hacktool set"
    family = "None"
    hacker = "None"
    hash1 = "b4f3787a19b71c47bc4357a5a77ffb456e2f71fd858079d93e694a6a79f66533"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed 0day Repos"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\cmd.exe\" /k wusa c:\\users\\" ascii
    $s2 = "D:\\gitpoc\\UAC\\src\\x64\\Release\\lpe.pdb" fullword ascii
    $s3 = "Folder Created: " fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 700KB and 2 of them )
}