rule MAL_BurningUmbrella_Sample_6 {
  meta:
    author = Spider
    comment = None
    date = 2018-05-04
    description = Detects malware sample from Burning Umbrella report
    family = 6
    hacker = None
    hash1 = 49ef2b98b414c321bcdbab107b8fa71a537958fe1e05ae62aaa01fe7773c3b4b
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://401trg.pw/burning-umbrella/
    threatname = MAL[BurningUmbrella]/Sample.6
    threattype = BurningUmbrella
  strings:
    $s1 = "ExecuteFile=\"hidcon:nowait:\\\"Word\\\\r.bat\\\"\"" fullword ascii
    $s2 = "InstallPath=\"%Appdata%\\\\Microsoft\"" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}