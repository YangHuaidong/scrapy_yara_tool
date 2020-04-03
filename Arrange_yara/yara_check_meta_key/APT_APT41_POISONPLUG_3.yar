rule APT_APT41_POISONPLUG_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-08-07"
    description = "Detects APT41 malware POISONPLUG"
    family = "None"
    hacker = "None"
    hash1 = "70c03ce5c80aca2d35a5555b0532eedede24d4cc6bdb32a2c8f7e630bba5f26e"
    judge = "black"
    reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Rundll32.exe \"%s\", DisPlay 64" fullword ascii
    $s2 = "tcpview.exe" fullword ascii
    $s3 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" fullword ascii /* reversed goodware string 'Software\\Microsoft\\Windows\\CurrentVersion\\Run' */
    $s4 = "AxEeulaVteSgeR" fullword ascii /* reversed goodware string 'RegSetValueExA' */
    $s5 = "%04d-%02d-%02d_%02d-%02d-%02d.dmp" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 900KB and 3 of them
}