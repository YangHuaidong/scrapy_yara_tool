rule CookieTools {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file CookieTools.exe"
    family = "None"
    hacker = "None"
    hash = "b6a3727fe3d214f4fb03aa43fb2bc6fadc42c8be"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "http://210.73.64.88/doorway/cgi-bin/getclientip.asp?IP=" fullword ascii
    $s2 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
    $s3 = "Connection Closed Gracefully.;Could not bind socket. Address and port are alread" wide
    $s8 = "OnGetPasswordP" fullword ascii
    $s12 = "http://www.chinesehack.org/" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 5000KB and 4 of them
}