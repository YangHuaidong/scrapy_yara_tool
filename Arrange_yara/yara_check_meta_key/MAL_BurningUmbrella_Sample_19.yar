rule MAL_BurningUmbrella_Sample_19 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-05-04"
    description = "Detects malware sample from Burning Umbrella report"
    family = "None"
    hacker = "None"
    hash1 = "05e2912f2a593ba16a5a094d319d96715cbecf025bf88bb0293caaf6beb8bc20"
    hash2 = "e7bbdb275773f43c8e0610ad75cfe48739e0a2414c948de66ce042016eae0b2e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://401trg.pw/burning-umbrella/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Cryption.dll" fullword ascii
    $s2 = "tran.exe" fullword ascii
    $s3 = "Kernel.dll" fullword ascii
    $s4 = "Now ready to get the file %s!" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and 3 of them
}