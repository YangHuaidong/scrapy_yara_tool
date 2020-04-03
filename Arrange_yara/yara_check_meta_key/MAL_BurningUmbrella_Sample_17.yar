rule MAL_BurningUmbrella_Sample_17 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-05-04"
    description = "Detects malware sample from Burning Umbrella report"
    family = "None"
    hacker = "None"
    hash1 = "fa380dac35e16da01242e456f760a0e75c2ce9b68ff18cfc7cfdd16b2f4dec56"
    hash2 = "854b64155f9ceac806b49f3e352949cc292e5bc33f110d965cf81a93f78d2f07"
    hash3 = "1e462d8968e8b6e8784d7ecd1d60249b41cf600975d2a894f15433a7fdf07a0f"
    hash4 = "3cdc149e387ec4a64cce1191fc30b8588df4a2947d54127eae43955ce3d08a01"
    hash5 = "a026b11e15d4a81a449d20baf7cbd7b8602adc2644aa4bea1e55ff1f422c60e3"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://401trg.pw/burning-umbrella/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "syshell" fullword wide
    $s2 = "Normal.dotm" fullword ascii
    $s3 = "Microsoft Office Word" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 400KB and all of them
}