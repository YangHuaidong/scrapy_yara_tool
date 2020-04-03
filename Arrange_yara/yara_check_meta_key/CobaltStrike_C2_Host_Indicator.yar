rule CobaltStrike_C2_Host_Indicator {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-08-16"
    description = "Detects CobaltStrike C2 host artifacts"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $c2_indicator_fp = "#Host: %s"
    $c2_indicator = "#Host:"
  condition:
    $c2_indicator and not $c2_indicator_fp
    and not uint32(0) == 0x0a786564
    and not uint32(0) == 0x0a796564
}