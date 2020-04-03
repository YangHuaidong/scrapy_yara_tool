rule Hacktools_CN_Burst_sql {
  meta:
    author = "Spider"
    comment = "None"
    date = "17.11.14"
    description = "Disclosed hacktool set - file sql.exe"
    family = "None"
    hacker = "None"
    hash = "d5139b865e99b7a276af7ae11b14096adb928245"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "s.exe %s %s %s %s %d /save" fullword ascii
    $s2 = "s.exe start error...%d" fullword ascii
    $s4 = "EXEC sp_addextendedproc xp_cmdshell,'xplog70.dll'" fullword ascii
    $s7 = "EXEC master..xp_cmdshell 'wscript.exe cc.js'" fullword ascii
    $s10 = "Result.txt" fullword ascii
    $s11 = "Usage:sql.exe [options]" fullword ascii
    $s17 = "%s root %s %d error" fullword ascii
    $s18 = "Pass.txt" fullword ascii
    $s20 = "SELECT sillyr_at_gmail_dot_com INTO DUMPFILE '%s\\\\sillyr_x.so' FROM sillyr_x" fullword ascii
  condition:
    6 of them
}