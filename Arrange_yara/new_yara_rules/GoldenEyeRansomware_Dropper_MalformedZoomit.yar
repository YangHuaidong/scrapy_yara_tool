rule GoldenEyeRansomware_Dropper_MalformedZoomit {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-12-06"
    description = "Auto-generated rule - file b5ef16922e2c76b09edd71471dd837e89811c5e658406a8495c1364d0d9dc690"
    family = "None"
    hacker = "None"
    hash1 = "b5ef16922e2c76b09edd71471dd837e89811c5e658406a8495c1364d0d9dc690"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/jp2SkT"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "ZoomIt - Sysinternals: www.sysinternals.com" fullword ascii
    $n1 = "Mark Russinovich" wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 800KB and $s1 and not $n1 )
}