rule RangeScan {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file RangeScan.exe"
    family = "None"
    hacker = "None"
    hash = "bace2c65ea67ac4725cb24aa9aee7c2bec6465d7"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "RangeScan.EXE" fullword wide
    $s4 = "<br><p align=\"center\"><b>RangeScan " fullword ascii
    $s9 = "Produced by isn0" fullword ascii
    $s10 = "RangeScan" fullword wide
    $s20 = "%d-%d-%d %d:%d:%d" fullword ascii
  condition:
    3 of them
}