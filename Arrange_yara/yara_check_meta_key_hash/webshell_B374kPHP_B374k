rule webshell_B374kPHP_B374k {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file B374k.php"
    family = "None"
    hacker = "None"
    hash = "bed7388976f8f1d90422e8795dff1ea6"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Http://code.google.com/p/b374k-shell" fullword
    $s1 = "$_=str_rot13('tm'.'vas'.'yngr');$_=str_rot13(strrev('rqb'.'prq'.'_'.'46r'.'fno'"
    $s3 = "Jayalah Indonesiaku & Lyke @ 2013" fullword
    $s4 = "B374k Vip In Beautify Just For Self" fullword
  condition:
    1 of them
}