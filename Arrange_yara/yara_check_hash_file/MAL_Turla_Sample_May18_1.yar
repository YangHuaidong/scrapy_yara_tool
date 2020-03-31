rule MAL_Turla_Sample_May18_1 {
  meta:
    author = Spider
    comment = None
    date = 2018-05-03
    description = Detects Turla samples
    family = May18
    hacker = None
    hash1 = 4c49c9d601ebf16534d24d2dd1cab53fde6e03902758ef6cff86be740b720038
    hash2 = 77cbd7252a20f2d35db4f330b9c4b8aa7501349bc06bbcc8f40ae13d01ae7f8f
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://twitter.com/omri9741/status/991942007701598208
    threatname = MAL[Turla]/Sample.May18.1
    threattype = Turla
  strings:
    $x1 = "sc %s create %s binPath= \"cmd.exe /c start %%SystemRoot%%\\%s\">>%s" fullword ascii
    $x2 = "cmd.exe /c start %%SystemRoot%%\\%s" fullword ascii
    $x3 = "cmd.exe /c %s\\%s -s %s:%s:%s -c \"%s %s /wait 1\">>%s" fullword ascii
    $x4 = "Read InjectLog[%dB]********************************" fullword ascii
    $x5 = "%s\\System32\\011fe-3420f-ff0ea-ff0ea.tmp" fullword ascii
    $x6 = "**************************** Begin ini %s [%d]***********************************************" fullword ascii
    $x7 = "%s -o %s -i %s -d exec2 -f %s" fullword ascii
    $x8 = "Logon to %s failed: code %d(User:%s,Pass:%s)" fullword ascii
    $x9 = "system32\\dxsnd32x.exe" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 500KB and 1 of them
}