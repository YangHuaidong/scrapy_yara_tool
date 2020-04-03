rule MSSqlPass {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file MSSqlPass.exe"
    family = "None"
    hacker = "None"
    hash = "172b4e31ed15d1275ac07f3acbf499daf9a055d7"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Reveals the passwords stored in the Registry by Enterprise Manager of SQL Server" wide
    $s1 = "empv.exe" fullword wide
    $s2 = "Enterprise Manager PassView" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 120KB and all of them
}