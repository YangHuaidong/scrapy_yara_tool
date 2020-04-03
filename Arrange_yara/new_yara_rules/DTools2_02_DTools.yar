rule DTools2_02_DTools {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file DTools.exe"
    family = "None"
    hacker = "None"
    hash = "9f99771427120d09ec7afa3b21a1cb9ed720af12"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "kernel32.dll" ascii
    $s1 = "TSETPASSWORDFORM" fullword wide
    $s2 = "TGETNTUSERNAMEFORM" fullword wide
    $s3 = "TPORTFORM" fullword wide
    $s4 = "ShellFold" fullword ascii
    $s5 = "DefaultPHotLigh" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}