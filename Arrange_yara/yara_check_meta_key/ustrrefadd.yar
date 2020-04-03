rule ustrrefadd {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file ustrrefadd.dll"
    family = "None"
    hacker = "None"
    hash = "b371b122460951e74094f3db3016264c9c8a0cfa"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "E-Mail  : admin@luocong.com" fullword ascii
    $s1 = "Homepage: http://www.luocong.com" fullword ascii
    $s2 = ": %d  -  " fullword ascii
    $s3 = "ustrreffix.dll" fullword ascii
    $s5 = "Ultra String Reference plugin v%d.%02d" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 320KB and all of them
}