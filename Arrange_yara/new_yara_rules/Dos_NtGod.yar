rule Dos_NtGod {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file NtGod.exe"
    family = "None"
    hacker = "None"
    hash = "adefd901d6bbd8437116f0170b9c28a76d4a87bf"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "\\temp\\NtGodMode.exe" ascii
    $s4 = "NtGodMode.exe" fullword ascii
    $s10 = "ntgod.bat" fullword ascii
    $s19 = "sfxcmd" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 250KB and all of them
}