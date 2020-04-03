rule hatman_loadoff : hatman {
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
    $loadoff_be = { 80 60 00 04  48 00 ?? ??  70 60 ff ff  28 00 00 00
    40 82 ?? ??  28 03 00 00  41 82 ?? ??              }
    $loadoff_le = { 04 00 60 80  ?? ?? 00 48  ff ff 60 70  00 00 00 28
    ?? ?? 82 40  00 00 03 28  ?? ?? 82 41              }
  condition:
    $loadoff_be or $loadoff_le
}