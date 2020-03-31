rule MAL_Turla_Agent_BTZ {
  meta:
    author = Spider
    comment = None
    date = 2018-04-12
    description = Detects Turla Agent.BTZ
    family = BTZ
    hacker = None
    hash1 = c4a1cd6916646aa502413d42e6e7441c6e7268926484f19d9acbf5113fc52fc8
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://www.gdatasoftware.com/blog/2014/11/23937-the-uroburos-case-new-sophisticated-rat-identified
    threatname = MAL[Turla]/Agent.BTZ
    threattype = Turla
  strings:
    $x1 = "1dM3uu4j7Fw4sjnbcwlDqet4F7JyuUi4m5Imnxl1pzxI6as80cbLnmz54cs5Ldn4ri3do5L6gs923HL34x2f5cvd0fk6c1a0s" fullword ascii
    $x3 = "mstotreg.dat" fullword ascii
    $x4 = "Bisuninst.bin" fullword ascii
    $x5 = "mfc42l00.pdb" fullword ascii
    $x6 = "ielocal~f.tmp" fullword ascii
    $s1 = "%s\\1.txt" fullword ascii
    $s2 = "%windows%" fullword ascii
    $s3 = "%s\\system32" fullword ascii
    $s4 = "\\Help\\SYSTEM32\\" fullword ascii
    $s5 = "%windows%\\mfc42l00.pdb" fullword ascii
    $s6 = "Size of log(%dB) is too big, stop write." fullword ascii
    $s7 = "Log: Size of log(%dB) is too big, stop write." fullword ascii
    $s8 = "%02d.%02d.%04d Log begin:" fullword ascii
    $s9 = "\\system32\\win.com" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and (
    1 of ($x*) or
    4 of them
}