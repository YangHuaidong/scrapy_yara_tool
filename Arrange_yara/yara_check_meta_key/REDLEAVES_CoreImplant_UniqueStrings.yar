rule REDLEAVES_CoreImplant_UniqueStrings {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Strings identifying the core REDLEAVES RAT in its deobfuscated state"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"
    threatname = "None"
    threattype = "None"
  strings:
    $unique2 = "RedLeavesSCMDSimulatorMutex" nocase wide ascii
    $unique4 = "red_autumnal_leaves_dllmain.dll" wide ascii
    $unique7 = "\\NamePipe_MoreWindows" wide ascii
  condition:
    any of them
}