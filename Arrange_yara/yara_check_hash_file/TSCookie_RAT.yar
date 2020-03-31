rule TSCookie_RAT {
  meta:
    author = Spider
    comment = None
    date = 2018-03-06
    description = Detects TSCookie RAT
    family = None
    hacker = None
    hash1 = 2bd13d63797864a70b775bd1994016f5052dc8fd1fd83ce1c13234b5d304330d
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://blog.jpcert.or.jp/2018/03/malware-tscooki-7aa0.html
    threatname = TSCookie[RAT
    threattype = RAT.yar
  strings:
    $x1 = "[-] DecryptPassword_Outlook failed(err=%d)" fullword ascii
    $x2 = "----------------------- Firefox Passwords ------------------" fullword ascii
    $x3 = "--------------- Outlook Passwords ------------------" fullword ascii
    $x4 = "----------------------- IE Passwords ------------------" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and (
    ( pe.exports("DoWork") and pe.exports("PrintF") ) or
    1 of them
}