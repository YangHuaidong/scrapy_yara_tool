rule ASPack_ASPACK {
   meta:
      description = "Disclosed hacktool set (old stuff) - file ASPACK.EXE"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      date = "23.11.14"
      score = 60
      hash = "c589e6fd48cfca99d6335e720f516e163f6f3f42"
   strings:
      $s0 = "ASPACK.EXE" fullword wide
      $s5 = "CLOSEDFOLDER" fullword wide
      $s10 = "ASPack compressor" fullword wide
   condition:
      all of them
}