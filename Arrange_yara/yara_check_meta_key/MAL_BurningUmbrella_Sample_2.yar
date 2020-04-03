rule MAL_BurningUmbrella_Sample_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-05-04"
    description = "Detects malware sample from Burning Umbrella report"
    family = "None"
    hacker = "None"
    hash1 = "801a64a730fc8d80e17e59e93533c1455686ca778e6ba99cf6f1971a935eda4c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://401trg.pw/burning-umbrella/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = { 40 00 00 e0 63 68 72 6f 6d 67 75 78 }
    $s2 = { 40 00 00 e0 77 62 68 75 74 66 6f 61 }
    $s3 = "ActiveX Manager" wide
  condition:
    uint16(0) == 0x5a4d and filesize < 3000KB and
    $s1 in (0..1024) and
    $s2 in (0..1024) and
    $s3
}