rule Cmdshell32 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file Cmdshell32.exe"
    family = "None"
    hacker = "None"
    hash = "3c41116d20e06dcb179e7346901c1c11cd81c596"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "cmdshell.exe" fullword wide
    $s2 = "cmdshell" fullword ascii
    $s3 = "[Root@CmdShell ~]#" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 62KB and all of them
}