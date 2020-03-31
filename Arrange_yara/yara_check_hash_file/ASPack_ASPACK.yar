rule ASPack_ASPACK {
  meta:
    author = Spider
    comment = None
    date = 23.11.14
    description = Disclosed hacktool set (old stuff) - file ASPACK.EXE
    family = None
    hacker = None
    hash = c589e6fd48cfca99d6335e720f516e163f6f3f42
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 60
    threatname = ASPack[ASPACK
    threattype = ASPACK.yar
  strings:
    $s0 = "ASPACK.EXE" fullword wide
    $s5 = "CLOSEDFOLDER" fullword wide
    $s10 = "ASPack compressor" fullword wide
  condition:
    all of them
}