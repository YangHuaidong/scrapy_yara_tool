rule WoolenGoldfish_Sample_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/25"
    description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
    family = "None"
    hacker = "None"
    hash = "7ad0eb113bc575363a058f4bf21dbab8c8f7073a"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/NpJpVZ"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Cannot execute (%d)" fullword ascii
    $s16 = "SvcName" fullword ascii
  condition:
    all of them
}