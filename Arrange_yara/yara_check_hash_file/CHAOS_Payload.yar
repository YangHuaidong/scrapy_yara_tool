rule CHAOS_Payload {
  meta:
    author = Spider
    comment = None
    date = 2017-07-15
    description = Detects a CHAOS back connect payload
    family = None
    hacker = None
    hash1 = 0962fcfcb1b52df148720c2112b036e75755f09279e3ebfce1636739af9b4448
    hash2 = 5c3553345f824b7b6de09ccb67d834e428b8df17443d98816471ca28f5a11424
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://github.com/tiagorlampert/CHAOS
    score = 80
    threatname = CHAOS[Payload
    threattype = Payload.yar
  strings:
    $x1 = { 2f 43 48 41 4f 53 00 02 73 79 6e 63 2f 61 74 6f 6d 69 63 }
  condition:
    ( uint16(0) == 0x5a4d and filesize < 15000KB and all of them )
}