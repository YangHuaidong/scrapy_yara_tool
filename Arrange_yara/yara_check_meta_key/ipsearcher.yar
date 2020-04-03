rule ipsearcher {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file ipsearcher.dll"
    family = "None"
    hacker = "None"
    hash = "1e96e9c5c56fcbea94d26ce0b3f1548b224a4791"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "http://www.wzpg.com" fullword ascii
    $s1 = "ipsearcher\\ipsearcher\\Release\\ipsearcher.pdb" fullword ascii
    $s3 = "_GetAddress" fullword ascii
    $s5 = "ipsearcher.dll" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 140KB and all of them
}