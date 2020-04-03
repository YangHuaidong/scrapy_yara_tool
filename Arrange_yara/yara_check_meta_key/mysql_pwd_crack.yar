rule mysql_pwd_crack {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file mysql_pwd_crack.exe"
    family = "None"
    hacker = "None"
    hash = "57d1cb4d404688804a8c3755b464a6e6248d1c73"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "mysql_pwd_crack 127.0.0.1 -x 3306 -p root -d userdict.txt" fullword ascii
    $s2 = "Successfully --> username %s password %s " fullword ascii
    $s3 = "zhouzhen@gmail.com http://zhouzhen.eviloctal.org" fullword ascii
    $s4 = "-a automode  automatic crack the mysql password " fullword ascii
    $s5 = "mysql_pwd_crack 127.0.0.1 -x 3306 -a" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}