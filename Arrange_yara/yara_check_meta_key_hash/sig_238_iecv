rule sig_238_iecv {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file iecv.exe"
    family = "None"
    hacker = "None"
    hash = "6e6e75350a33f799039e7a024722cde463328b6d"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Edit The Content Of Cookie " fullword wide
    $s3 = "Accessories\\wordpad.exe" fullword ascii
    $s4 = "gorillanation.com" fullword ascii
    $s5 = "Before editing the content of a cookie, you should close all windows of Internet" ascii
    $s12 = "http://nirsoft.cjb.net" fullword ascii
  condition:
    all of them
}