rule tools_Sqlcmd {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file Sqlcmd.exe"
    family = "None"
    hacker = "None"
    hash = "99d56476e539750c599f76391d717c51c4955a33"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "[Usage]:  %s <HostName|IP> <UserName> <Password>" fullword ascii
    $s1 = "=============By uhhuhy(Feb 18,2003) - http://www.cnhonker.net=============" fullword ascii /* PEStudio Blacklist: os */
    $s4 = "Cool! Connected to SQL server on %s successfully!" fullword ascii
    $s5 = "EXEC master..xp_cmdshell \"%s\"" fullword ascii
    $s6 = "=======================Sqlcmd v0.21 For HScan v1.20=======================" fullword ascii
    $s10 = "Error,exit!" fullword ascii
    $s11 = "Sqlcmd>" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 40KB and 3 of them
}