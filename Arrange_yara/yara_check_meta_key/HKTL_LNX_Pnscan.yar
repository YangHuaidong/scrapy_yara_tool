rule HKTL_LNX_Pnscan {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-05-27"
    description = "Detects Pnscan port scanner"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://github.com/ptrrkssn/pnscan"
    score = 55
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "-R<hex list>   Hex coded response string to look for." fullword ascii
    $x2 = "This program implements a multithreaded TCP port scanner." ascii wide
  condition:
    filesize < 6000KB and 1 of them
}