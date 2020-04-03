rule SUSP_XORed_URL_in_EXE {
  meta:
    author = "Spider"
    comment = "None"
    date = "2020-03-09"
    description = "Detects an XORed URL in an executable"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://twitter.com/stvemillertime/status/1237035794973560834"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "http://" xor
    $s2 = "https://" xor
    $f1 = "http://" ascii
    $f2 = "https://" ascii
  condition:
    uint16(0) == 0x5a4d and
    filesize < 2000KB and (
    ( $s1 and #s1 > #f1 ) or
    ( $s2 and #s2 > #f2 )
}