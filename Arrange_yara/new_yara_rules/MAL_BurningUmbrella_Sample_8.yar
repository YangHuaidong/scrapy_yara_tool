rule MAL_BurningUmbrella_Sample_8 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-05-04"
    description = "Detects malware sample from Burning Umbrella report"
    family = "None"
    hacker = "None"
    hash1 = "73270fe9bca94fead1b5b38ddf69fae6a42e574e3150d3e3ab369f5d37d93d88"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://401trg.pw/burning-umbrella/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "cmd /c open %s" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 400KB and 1 of them
}