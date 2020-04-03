rule hatman_mftmsr : hatman {
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
    $mfmsr_be = { 7c 63 00 a6 }
    $mfmsr_le = { a6 00 63 7c }
    $mtmsr_be = { 7c 63 01 24 }
    $mtmsr_le = { 24 01 63 7c }
  condition:
    ($mfmsr_be and $mtmsr_be) or ($mfmsr_le and $mtmsr_le)
}