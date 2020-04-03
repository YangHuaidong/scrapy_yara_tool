rule VUBrute_config {
  meta:
    author = "Spider"
    comment = "None"
    date = "22.11.14"
    description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file config.ini"
    family = "None"
    hacker = "None"
    hash = "b9f66b9265d2370dab887604921167c11f7d93e9"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/xiIphp"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "Restore=1" fullword ascii
    $s6 = "Thread=" ascii
    $s7 = "Running=1" fullword ascii
    $s8 = "CheckCombination=" fullword ascii
    $s10 = "AutoSave=1.000000" fullword ascii
    $s12 = "TryConnect=" ascii
    $s13 = "Tray=" ascii
  condition:
    all of them
}