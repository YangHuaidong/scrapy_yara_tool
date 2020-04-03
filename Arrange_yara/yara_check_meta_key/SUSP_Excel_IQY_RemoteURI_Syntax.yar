rule SUSP_Excel_IQY_RemoteURI_Syntax {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-08-17"
    description = "Detects files with Excel IQY RemoteURI syntax"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://twitter.com/ItsReallyNick/status/1030330473954897920"
    score = 65
    threatname = "None"
    threattype = "None"
  strings:
    $URL = "http"
  condition:
    uint32(0) == 0x0d424557 and uint32(4) == 0x0a0d310a
    and filesize < 1MB
    and $URL
}