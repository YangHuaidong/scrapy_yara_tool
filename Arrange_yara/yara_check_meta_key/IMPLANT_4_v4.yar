rule IMPLANT_4_v4 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-10"
    description = "BlackEnergy / Voodoo Bear Implant by APT28"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $DK_format1 = "/c format %c: /Y /Q" ascii
    $DK_format2 = "/c format %c: /Y /X /FS:NTFS" ascii
    $DK_physicaldrive = "PhysicalDrive%d" wide
    $DK_shutdown = "shutdown /r /t %d"
  condition:
    uint16(0) == 0x5A4D and all of ($DK*)
}