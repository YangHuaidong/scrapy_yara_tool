rule Win32_klock {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file klock.dll
    family = None
    hacker = None
    hash = 7addce4434670927c4efaa560524680ba2871d17
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = Win32[klock
    threattype = klock.yar
  strings:
    $s1 = "klock.dll" fullword ascii
    $s2 = "Erreur : impossible de basculer le bureau ; SwitchDesktop : " fullword wide
    $s3 = "klock de mimikatz pour Windows" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 250KB and all of them
}