rule OpHoneybee_MaoCheng_Dropper {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-03-03"
    description = "Detects MaoCheng dropper from Operation Honeybee"
    family = "None"
    hacker = "None"
    hash1 = "35904f482d37f5ce6034d6042bae207418e450f4"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/JAHZVL"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "\\MaoCheng\\Release\\" ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 600KB and 1 of them
}