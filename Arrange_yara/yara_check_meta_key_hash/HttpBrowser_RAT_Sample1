rule HttpBrowser_RAT_Sample1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-08-06"
    description = "Threat Group 3390 APT Sample - HttpBrowser RAT Sample update.hancominc.com"
    family = "None"
    hacker = "None"
    hash1 = "be334d1f8fa65a723af65200a166c2bbdb06690c8b30fafe772600e4662fc68b"
    hash2 = "1052ad7f4d49542e4da07fa8ea59c15c40bc09a4d726fad023daafdf05866ebb"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://snip.ly/giNB"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "update.hancominc.com" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and $s0
}