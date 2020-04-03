rule BypassUac_9 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Auto-generated rule - file BypassUac.zip"
    family = "None"
    hacker = "None"
    hash = "93c2375b2e4f75fc780553600fbdfd3cb344e69d"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "/x86/BypassUac.exe" fullword ascii
    $s1 = "/x64/BypassUac.exe" fullword ascii
    $s2 = "/x86/BypassUacDll.dll" fullword ascii
    $s3 = "/x64/BypassUacDll.dll" fullword ascii
    $s15 = "BypassUac" fullword ascii
  condition:
    all of them
}