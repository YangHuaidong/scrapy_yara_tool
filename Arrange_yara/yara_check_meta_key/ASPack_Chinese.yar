rule ASPack_Chinese {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file ASPack Chinese.ini"
    family = "None"
    hacker = "None"
    hash = "02a9394bc2ec385876c4b4f61d72471ac8251a8e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "= Click here if you want to get your registered copy of ASPack" fullword ascii
    $s1 = ";  For beginning of translate - copy english.ini into the yourlanguage.ini" fullword ascii
    $s2 = "E-Mail:                      shinlan@km169.net" fullword ascii
    $s8 = ";  Please, translate text only after simbol '='" fullword ascii
    $s19 = "= Compress with ASPack" fullword ascii
  condition:
    all of them
}