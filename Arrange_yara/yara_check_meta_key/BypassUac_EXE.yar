rule BypassUac_EXE {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Auto-generated rule - file BypassUacDll.aps"
    family = "None"
    hacker = "None"
    hash = "58d7b24b6870cb7f1ec4807d2f77dd984077e531"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Wole32.dll" wide
    $s3 = "System32\\migwiz" wide
    $s4 = "System32\\migwiz\\CRYPTBASE.dll" wide
    $s5 = "Elevation:Administrator!new:" wide
    $s6 = "BypassUac" wide
  condition:
    all of them
}