rule HTA_Embedded {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-06-21"
    description = "Detects an embedded HTA file"
    family = "None"
    hacker = "None"
    hash1 = "ca7b653cf41e980c44311b2cd701ed666f8c1dbc"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://twitter.com/msftmmpc/status/877396932758560768"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<hta:application windowstate=\"minimize\"/>"
  condition:
    $s1 and not $s1 in (0..50000)
}