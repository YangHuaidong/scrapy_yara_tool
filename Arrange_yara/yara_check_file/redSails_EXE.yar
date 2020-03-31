rule redSails_EXE {
  meta:
    author = Spider
    comment = None
    date = 2017-10-02
    description = Detects Red Sails Hacktool by WinDivert references
    family = None
    hacker = None
    hash1 = 7a7861d25b0c038d77838ecbd5ea5674650ad4f5faf7432a6f3cfeb427433fac
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://github.com/BeetleChunks/redsails
    threatname = redSails[EXE
    threattype = EXE.yar
  strings:
    $s1 = "bWinDivert64.dll" fullword ascii
    $s2 = "bWinDivert32.dll" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 6000KB and all of them )
}