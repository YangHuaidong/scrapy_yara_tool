rule VUBrute_VUBrute {
  meta:
    author = "Spider"
    comment = "None"
    date = "22.11.14"
    description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file VUBrute.exe"
    family = "None"
    hacker = "None"
    hash = "166fa8c5a0ebb216c832ab61bf8872da556576a7"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Text Files (*.txt);;All Files (*)" fullword ascii
    $s1 = "http://ubrute.com" fullword ascii
    $s11 = "IP - %d; Password - %d; Combination - %d" fullword ascii
    $s14 = "error.txt" fullword ascii
  condition:
    all of them
}