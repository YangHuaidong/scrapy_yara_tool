rule CobaltStrike_Sleep_Decoder_Indicator {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-08-16"
    description = "Detects CobaltStrike sleep_mask decoder"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $sleep_decoder = { 8b 07 8b 57 04 83 c7 08 85 c0 75 2c }
  condition:
    $sleep_decoder
}