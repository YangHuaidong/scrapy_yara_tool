rule DK_Brute {
  meta:
    author = Spider
    comment = None
    date = 22.11.14
    description = PoS Scammer Toolbox - http://goo.gl/xiIphp - file DK Brute.exe
    family = None
    hacker = None
    hash = 93b7c3a01c41baecfbe42461cb455265f33fbc3d
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://goo.gl/xiIphp
    score = 70
    threatname = DK[Brute
    threattype = Brute.yar
  strings:
    $s6 = "get_CrackedCredentials" fullword ascii
    $s13 = "Same port used for two different protocols:" fullword wide
    $s18 = "coded by fLaSh" fullword ascii
    $s19 = "get_grbToolsScaningCracking" fullword ascii
  condition:
    all of them
}