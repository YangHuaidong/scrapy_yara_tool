rule Pc_xai {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file xai.exe"
    family = "None"
    hacker = "None"
    hash = "f285a59fd931ce137c08bd1f0dae858cc2486491"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Powered by CoolDiyer @ C.Rufus Security Team 05/19/2008  http://www.xcodez.com/" fullword wide
    $s2 = "%SystemRoot%\\System32\\" fullword ascii
    $s3 = "%APPDATA%\\" fullword ascii
    $s4 = "---- C.Rufus Security Team ----" fullword wide
    $s5 = "www.snzzkz.com" fullword wide
    $s6 = "%CommonProgramFiles%\\" fullword ascii
    $s7 = "GetRand.dll" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}