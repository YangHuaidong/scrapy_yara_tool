rule BypassUac2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Auto-generated rule - file BypassUac2.zip"
    family = "None"
    hacker = "None"
    hash = "ef3e7dd2d1384ecec1a37254303959a43695df61"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "/BypassUac/BypassUac/BypassUac_Utils.cpp" fullword ascii
    $s1 = "/BypassUac/BypassUacDll/BypassUacDll.aps" fullword ascii
    $s3 = "/BypassUac/BypassUac/BypassUac.ico" fullword ascii
  condition:
    all of them
}