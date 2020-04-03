rule ALFA_SHELL {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-09-21"
    description = "Detects web shell often used by Iranian APT groups"
    family = "None"
    hacker = "None"
    hash1 = "a39d8823d54c55e60a7395772e50d116408804c1a5368391a1e5871dbdc83547"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research - APT33"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "$OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64')" ascii
    $x2 = "#solevisible@gmail.com" fullword ascii
    $x3 = "'login_page' => '500',//gui or 500 or 403 or 404" fullword ascii
    $x4 = "$GLOBALS['__ALFA__']" fullword ascii
    $x5 = "if(!function_exists('b'.'as'.'e6'.'4_'.'en'.'co'.'de')" ascii
    $f1 = { 76 2f 38 76 2f 36 76 2f 2b 76 2f 2f 66 38 46 27 29 3b 3f 3e 0d 0a }
  condition:
    ( filesize < 900KB and 2 of ($x*) or $f1 at (filesize-22) )
}