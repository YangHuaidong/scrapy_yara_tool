rule StuxNet_dll {
  meta:
    author = Spider
    comment = None
    date = 2016-07-09
    description = Stuxnet Sample - file dll.dll
    family = None
    hacker = None
    hash1 = 9e392277f62206098cf794ddebafd2817483cfd57ec03c2e05e7c3c81e72f562
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Internal Research
    threatname = StuxNet[dll
    threattype = dll.yar
  strings:
    $s1 = "SUCKM3 FROM EXPLORER.EXE MOTH4FUCKA #@!" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and $s1
}