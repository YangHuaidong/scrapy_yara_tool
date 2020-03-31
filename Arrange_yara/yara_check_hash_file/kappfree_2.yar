rule kappfree_2 {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file kappfree.dll
    family = None
    hacker = None
    hash = 5d578df9a71670aa832d1cd63379e6162564fb6b
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = kappfree[2
    threattype = 2.yar
  strings:
    $s1 = "kappfree.dll" fullword ascii
    $s2 = "kappfree de mimikatz pour Windows (anti AppLocker)" fullword wide
    $s3 = "' introuvable !" fullword wide
    $s4 = "kiwi\\mimikatz" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}