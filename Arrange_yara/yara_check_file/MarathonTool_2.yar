rule MarathonTool_2 {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file MarathonTool.exe
    family = None
    hacker = None
    hash = 75b5d25cdaa6a035981e5a33198fef0117c27c9c
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = MarathonTool[2
    threattype = 2.yar
  strings:
    $s3 = "http://localhost/retomysql/pista.aspx?id_pista=1" fullword wide
    $s6 = "SELECT ASCII(SUBSTR(username,{0},1)) FROM USER_USERS" fullword wide
    $s17 = "/Blind SQL injection tool based in heavy queries" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}