rule APT_MAL_CN_Wocao_keylogger_file {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Rule for finding keylogger output files"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
    threatname = "None"
    threattype = "None"
  strings:
    $a = { 0d 0a 20 [3-10] 53 74 61 72 74 75 70 3a 20 [3] 20 [3] 20 [2] 20 [2] 3a [2] 3a [2] 20 }
  condition:
    all of them
}