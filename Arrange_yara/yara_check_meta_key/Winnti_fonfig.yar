rule Winnti_fonfig {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-25"
    description = "Winnti sample - file fonfig.exe"
    family = "None"
    hacker = "None"
    hash1 = "2c9882854a60c624ecf6b62b6c7cc7ed04cf4a29814aa5ed1f1a336854697641"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/VbvJtL"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "mciqtz.exe" fullword wide
    $s2 = "knat9y7m" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}