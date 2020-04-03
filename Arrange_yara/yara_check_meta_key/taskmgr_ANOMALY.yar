rule taskmgr_ANOMALY {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/16"
    description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file taskmgr.exe"
    family = "None"
    hacker = "None"
    hash = "e8b4d84a28e5ea17272416ec45726964fdf25883"
    judge = "black"
    nodeepdive = 1
    reference = "not set"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Windows Task Manager" fullword wide
    $s1 = "taskmgr.chm" fullword
    $s2 = "TmEndTaskHandler::" ascii
    $s3 = "CM_Request_Eject_PC" /* Win XP */
    $s4 = "NTShell Taskman Startup Mutex" fullword wide
  condition:
    ( filename == "taskmgr.exe" or filename == "Taskmgr.exe" ) and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
    and uint16(0) == 0x5a4d
    and filepath contains "C:\\"
    and not filepath contains "Package_for_RollupFix"
}