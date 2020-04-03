rule webshell_c99_madnet_smowu {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file smowu.php"
    family = "None"
    hacker = "None"
    hash = "3aaa8cad47055ba53190020311b0fb83"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "//Authentication" fullword
    $s1 = "$login = \"" fullword
    $s2 = "eval(gzinflate(base64_decode('"
    $s4 = "//Pass"
    $s5 = "$md5_pass = \""
    $s6 = "//If no pass then hash"
  condition:
    all of them
}