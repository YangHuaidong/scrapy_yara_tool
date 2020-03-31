rule CN_Honker_Interception3389_setup {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file setup.exe
    family = setup
    hacker = None
    hash = f5b2f86f8e7cdc00aa1cb1b04bc3d278eb17bf5c
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/Interception3389.setup
    threattype = Honker
  strings:
    $s0 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\%s" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "%s\\temp\\temp%d.bat" fullword ascii /* PEStudio Blacklist: strings */
    $s5 = "EventStartShell" fullword ascii /* PEStudio Blacklist: strings */
    $s6 = "del /f /q \"%s\"" fullword ascii
    $s7 = "\\wminotify.dll" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 400KB and all of them
}