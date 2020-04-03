rule CookieTools2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file CookieTools2.exe"
    family = "None"
    hacker = "None"
    hash = "cb67797f229fdb92360319e01277e1345305eb82"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "www.gxgl.com&www.gxgl.net" fullword wide
    $s2 = "ip.asp?IP=" fullword ascii
    $s3 = "MSIE 5.5;" fullword ascii
    $s4 = "SOFTWARE\\Borland\\" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 700KB and all of them
}