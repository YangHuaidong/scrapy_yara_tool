rule REDLEAVES_CoreImplant_UniqueStrings {
    meta:
        description = "Strings identifying the core REDLEAVES RAT in its deobfuscated state"
        reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"
        author = "USG"
    strings:
        $unique2 = "RedLeavesSCMDSimulatorMutex" nocase wide ascii
        $unique4 = "red_autumnal_leaves_dllmain.dll" wide ascii
        $unique7 = "\\NamePipe_MoreWindows" wide ascii
    condition:
      any of them
}