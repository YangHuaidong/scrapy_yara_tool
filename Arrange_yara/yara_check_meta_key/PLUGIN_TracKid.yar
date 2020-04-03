rule PLUGIN_TracKid {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file TracKid.dll"
    family = "None"
    hacker = "None"
    hash = "a114181b334e850d4b33e9be2794f5bb0eb59a09"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "E-mail: cracker_prince@163.com" fullword ascii
    $s1 = ".\\TracKid Log\\%s.txt" fullword ascii
    $s2 = "Coded by prince" fullword ascii
    $s3 = "TracKid.dll" fullword ascii
    $s4 = ".\\TracKid Log" fullword ascii
    $s5 = "%08x -- %s" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and 3 of them
}