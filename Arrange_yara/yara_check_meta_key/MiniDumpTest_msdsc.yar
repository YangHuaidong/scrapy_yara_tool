rule MiniDumpTest_msdsc {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-08-31"
    description = "Auto-generated rule - file msdsc.exe"
    family = "None"
    hacker = "None"
    hash = "477034933918c433f521ba63d2df6a27cc40a5833a78497c11fb0994d2fd46ba"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/giMini/RWMC/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "MiniDumpTest1.exe" fullword wide
    $s2 = "MiniDumpWithTokenInformation" fullword ascii
    $s3 = "MiniDumpTest1" fullword wide
    $s6 = "Microsoft 2008" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 20KB and all of them
}