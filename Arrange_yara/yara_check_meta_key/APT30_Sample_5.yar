rule APT30_Sample_5 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file ebf42e8b532e2f3b19046b028b5dfb23"
    family = "None"
    hacker = "None"
    hash = "1a2dd2a0555dc746333e7c956c58f7c4cdbabd4b"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Version 4.7.3001" fullword wide
    $s1 = "Copyright (c) Microsoft Corporation 2004" fullword wide
    $s3 = "Microsoft(R) is a registered trademark of Microsoft Corporation in the U" wide
    $s7 = "msmsgs" fullword wide
    $s10 = "----------------g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d" fullword ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}