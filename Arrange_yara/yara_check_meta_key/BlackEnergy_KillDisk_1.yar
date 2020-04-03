rule BlackEnergy_KillDisk_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-01-03"
    description = "Detects KillDisk malware from BlackEnergy"
    family = "None"
    hacker = "None"
    hash1 = "11b7b8a7965b52ebb213b023b6772dd2c76c66893fc96a18a9a33c8cf125af80"
    hash2 = "5d2b1abc7c35de73375dd54a4ec5f0b060ca80a1831dac46ad411b4fe4eac4c6"
    hash3 = "c7536ab90621311b526aefd56003ef8e1166168f038307ae960346ce8f75203d"
    hash4 = "f52869474834be5a6b5df7f8f0c46cbc7e9b22fa5cb30bee0f363ec6eb056b95"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
    score = 80
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "system32\\cmd.exe" fullword ascii
    $s1 = "system32\\icacls.exe" fullword wide
    $s2 = "/c del /F /S /Q %c:\\*.*" fullword ascii
    $s3 = "shutdown /r /t %d" fullword ascii
    $s4 = "/C /Q /grant " fullword wide
    $s5 = "%08X.tmp" fullword ascii
    $s6 = "/c format %c: /Y /X /FS:NTFS" fullword ascii
    $s7 = "/c format %c: /Y /Q" fullword ascii
    $s8 = "taskhost.exe" fullword wide /* Goodware String - occured 1 times */
    $s9 = "shutdown.exe" fullword wide /* Goodware String - occured 1 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 500KB and 8 of them
}