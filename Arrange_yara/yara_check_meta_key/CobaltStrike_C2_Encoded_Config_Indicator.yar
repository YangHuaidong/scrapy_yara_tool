rule CobaltStrike_C2_Encoded_Config_Indicator {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-08-16"
    description = "Detects CobaltStrike C2 encoded profile configuration"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $c2_enc_config = {69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? 69 6A 69 6B 69 6D ?? ?? ?? ?? 69 6D 69 6B 69 6D ?? ?? ?? ?? 69 6C 69 68 69 6B ?? ?? 69 6F 69 68 69 6B ?? ?? 69 6E 69 6A 68 69}
  condition:
    $c2_enc_config
}