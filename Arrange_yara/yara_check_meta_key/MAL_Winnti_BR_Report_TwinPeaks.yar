rule MAL_Winnti_BR_Report_TwinPeaks {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-07-24"
    description = "Detects Winnti samples"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://github.com/br-data/2019-winnti-analyse"
    threatname = "None"
    threattype = "None"
  strings:
    $cooper = "Cooper"
    $pattern = { e9 ea eb ec ed ee ef f0 }
  condition:
    uint16(0) == 0x5a4d and $cooper and ($pattern in (@cooper[1]..@cooper[1]+100))
}