rule InstGina {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file InstGina.exe"
    family = "None"
    hacker = "None"
    hash = "5317fbc39508708534246ef4241e78da41a4f31c"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "To Open Registry" fullword ascii
    $s4 = "I love Candy very much!!" ascii
    $s5 = "GinaDLL" fullword ascii
  condition:
    all of them
}