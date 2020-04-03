rule Dos_GetPass {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file GetPass.exe"
    family = "None"
    hacker = "None"
    hash = "d18d952b24110b83abd17e042f9deee679de6a1a"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "GetLogonS" ascii
    $s3 = "/showthread.php?t=156643" ascii
    $s8 = "To Run As Administ" ascii
    $s18 = "EnableDebugPrivileg" fullword ascii
    $s19 = "sedebugnameValue" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 890KB and all of them
}