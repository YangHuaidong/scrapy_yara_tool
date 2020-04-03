rule HKTL_Unkown_CN_Generate {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file Generate.exe"
    family = "None"
    hacker = "None"
    hash = "2cb4c3916271868c30c7b4598da697f59e9c7a12"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "C:\\TEMP\\" fullword ascii
    $s2 = "Connection Closed Gracefully.;Could not bind socket. Address and port are alread" wide
    $s3 = "$530 Please login with USER and PASS." fullword ascii
    $s4 = "_Shell.exe" fullword ascii
    $s5 = "ftpcWaitingPassword" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and 3 of them
}