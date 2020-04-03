rule x64_klock {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file klock.dll"
    family = "None"
    hacker = "None"
    hash = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Bienvenue dans un processus distant" fullword wide
    $s2 = "klock.dll" fullword ascii
    $s3 = "Erreur : le bureau courant (" fullword wide
    $s4 = "klock de mimikatz pour Windows" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 907KB and all of them
}