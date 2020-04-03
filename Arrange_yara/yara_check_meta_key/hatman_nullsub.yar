rule hatman_nullsub : hatman {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "None"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $nullsub = { ff ff 60 38 02 00 00 44 20 00 80 4e }
  condition:
    $nullsub
}