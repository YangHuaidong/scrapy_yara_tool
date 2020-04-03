rule OpHoneybee_MaoCheng_Dropper {
   meta:
      description = "Detects MaoCheng dropper from Operation Honeybee"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/JAHZVL"
      date = "2018-03-03"
      hash1 = "35904f482d37f5ce6034d6042bae207418e450f4"
   strings:
      $x1 = "\\MaoCheng\\Release\\" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and 1 of them
}