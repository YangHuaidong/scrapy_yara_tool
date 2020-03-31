rule MAL_BurningUmbrella_Sample_13 {
  meta:
    author = Spider
    comment = None
    date = 2018-05-04
    description = Detects malware sample from Burning Umbrella report
    family = 13
    hacker = None
    hash1 = d31374adc0b96a8a8b56438bbbc313061fd305ecee32a12738dd965910c8890f
    hash2 = c74a8e6c88f8501fb066ae07753efe8d267afb006f555811083c51c7f546cb67
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://401trg.pw/burning-umbrella/
    threatname = MAL[BurningUmbrella]/Sample.13
    threattype = BurningUmbrella
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and pe.imphash() == "75f201aa8b18e1c4f826b2fe0963b84f"
}