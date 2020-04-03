rule BypassUac_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Auto-generated rule - file BypassUacDll.dll"
    family = "None"
    hacker = "None"
    hash = "1974aacd0ed987119999735cad8413031115ce35"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "BypassUacDLL.dll" fullword wide
    $s1 = "\\Release\\BypassUacDll" ascii
    $s3 = "Win7ElevateDLL" fullword wide
    $s7 = "BypassUacDLL" fullword wide
  condition:
    3 of them
}