rule gina_zip_Folder_gina {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file gina.dll"
    family = "None"
    hacker = "None"
    hash = "e0429e1b59989cbab6646ba905ac312710f5ed30"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "NEWGINA.dll" fullword ascii
    $s1 = "LOADER ERROR" fullword ascii
    $s3 = "WlxActivateUserShell" fullword ascii
    $s6 = "WlxWkstaLockedSAS" fullword ascii
    $s13 = "WlxIsLockOk" fullword ascii
    $s14 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
    $s16 = "WlxShutdown" fullword ascii
    $s17 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
  condition:
    all of them
}