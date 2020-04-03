rule hscangui {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file hscangui.exe"
    family = "None"
    hacker = "None"
    hash = "af8aced0a78e1181f4c307c78402481a589f8d07"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "[%s]: Found \"FTP account: anyone/anyone@any.net\"  !!!" fullword ascii
    $s2 = "http://www.cnhonker.com" fullword ascii
    $s3 = "%s@ftpscan#Cracked account:  %s/%s" fullword ascii
    $s4 = "[%s]: Found \"FTP account: %s/%s\" !!!" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 220KB and 2 of them
}