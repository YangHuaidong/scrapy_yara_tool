rule Dos_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file 1.exe"
    family = "None"
    hacker = "None"
    hash = "b554f0687a12ec3a137f321cc15e052ff219f28c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "/churrasco/-->Usage: Churrasco.exe \"command to run\"" fullword ascii
    $s2 = "/churrasco/-->Done, command should have ran as SYSTEM!" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}