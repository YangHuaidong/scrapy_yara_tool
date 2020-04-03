rule APT_Tick_HomamDownloader_Jun18 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-06-23"
    description = "Detects HomamDownloader from Tick group incident - Weaponized USB"
    family = "None"
    hacker = "None"
    hash1 = "f817c9826089b49d251b8a09a0e9bf9b4b468c6e2586af60e50afe48602f0bec"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://researchcenter.paloaltonetworks.com/2018/06/unit42-tick-group-weaponized-secure-usb-drives-target-air-gapped-critical-systems/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "cmd /c hostname >>" fullword ascii
    $s2 = "Mstray.exe" fullword ascii
    $s3 = "msupdata.exe" fullword ascii
    $s5 = "Windows\\CurrentVersion\\run" fullword ascii
    $s6 = "Content-Type: */*" fullword ascii
    $s11 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" fullword ascii /* Goodware String - occured 3 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 30KB and 3 of them
}