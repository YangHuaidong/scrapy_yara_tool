rule CN_Honker_sig_3389_xp3389 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file xp3389.exe"
    family = "None"
    hacker = "None"
    hash = "d776eb7596803b5b94098334657667d34b60d880"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "echo \"fdenytsconnections\"=dword:00000000 >> c:\\reg.reg" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "echo [HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server] >" ascii /* PEStudio Blacklist: strings */
    $s3 = "echo \"Tsenabled\"=dword:00000001 >> c:\\reg.reg" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 20KB and all of them
}