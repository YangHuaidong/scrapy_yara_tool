rule BypassUac2 {
   meta:
      description = "Auto-generated rule - file BypassUac2.zip"
      author = "yarGen Yara Rule Generator"
      hash = "ef3e7dd2d1384ecec1a37254303959a43695df61"
   strings:
      $s0 = "/BypassUac/BypassUac/BypassUac_Utils.cpp" fullword ascii
      $s1 = "/BypassUac/BypassUacDll/BypassUacDll.aps" fullword ascii
      $s3 = "/BypassUac/BypassUac/BypassUac.ico" fullword ascii
   condition:
      all of them
}