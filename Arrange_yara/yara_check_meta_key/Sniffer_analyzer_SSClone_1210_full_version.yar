rule Sniffer_analyzer_SSClone_1210_full_version {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file Sniffer analyzer SSClone 1210 full version.exe"
    family = "None"
    hacker = "None"
    hash = "6882125babb60bd0a7b2f1943a40b965b7a03d4e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "http://www.vip80000.com/hot/index.html" fullword ascii
    $s1 = "GetConnectString" fullword ascii
    $s2 = "CnCerT.Safe.SSClone.dll" fullword ascii
    $s3 = "(*.JPG;*.BMP;*.GIF;*.ICO;*.CUR)|*.JPG;*.BMP;*.GIF;*.ICO;*.CUR|JPG" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 3580KB and all of them
}