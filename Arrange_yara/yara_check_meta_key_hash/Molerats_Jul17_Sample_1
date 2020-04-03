rule Molerats_Jul17_Sample_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-07-07"
    description = "Detects Molerats sample - July 2017"
    family = "None"
    hacker = "None"
    hash1 = "ebf2423b9de131eab1c61ac395cbcfc2ac3b15bd9c83b96ae0a48619a4a38d0a"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
    threatname = "None"
    threattype = "None"
  strings:
    /* {11804ce4-930a-4b09-bf70-9f1a95d0d70d}, Culture = neutral, PublicKeyToken=3e56350693f7355e */
    $s1 = "ezExODA0Y2U0LTkzMGEtNGIwOS1iZjcwLTlmMWE5NWQwZDcwZH0sIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49M2U1NjM1MDY5M2Y3MzU1ZQ==,[z]{c00" wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}