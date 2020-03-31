rule MAL_BurningUmbrella_Sample_1 {
  meta:
    author = Spider
    comment = None
    date = 2018-05-04
    description = Detects malware sample from Burning Umbrella report
    family = 1
    hacker = None
    hash1 = fcfe8fcf054bd8b19226d592617425e320e4a5bb4798807d6f067c39dfc6d1ff
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://401trg.pw/burning-umbrella/
    threatname = MAL[BurningUmbrella]/Sample.1
    threattype = BurningUmbrella
  strings:
    $s1 = { 40 00 00 e0 75 68 66 61 6f 68 6c 79 }
    $s2 = { 40 00 00 e0 64 6a 7a 66 63 6d 77 62 }
  condition:
    uint16(0) == 0x5a4d and filesize < 4000KB and (
    pe.imphash() == "baa93d47220682c04d92f7797d9224ce" and
    $s1 in (0..1024) and
    $s2 in (0..1024)
}