rule lamescan3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file lamescan3.exe"
    family = "None"
    hacker = "None"
    hash = "3130eefb79650dab2e323328b905e4d5d3a1d2f0"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "dic\\loginlist.txt" fullword ascii
    $s2 = "Radmin.exe" fullword ascii
    $s3 = "lamescan3.pdf!" fullword ascii
    $s4 = "dic\\passlist.txt" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 3740KB and all of them
}