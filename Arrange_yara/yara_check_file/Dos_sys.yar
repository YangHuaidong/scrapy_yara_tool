rule Dos_sys {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file sys.exe
    family = None
    hacker = None
    hash = b5837047443f8bc62284a0045982aaae8bab6f18
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = Dos[sys
    threattype = sys.yar
  strings:
    $s0 = "'SeDebugPrivilegeOpen " fullword ascii
    $s6 = "Author: Cyg07*2" fullword ascii
    $s12 = "from golds7n[LAG]'J" fullword ascii
    $s14 = "DAMAGE" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 150KB and all of them
}