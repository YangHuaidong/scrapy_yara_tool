rule SUSP_WER_Critical_HeapCorruption {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-10-18"
    description = "Detects a crashed application that crashed due to a heap corruption error (could be a sign of exploitation)"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://twitter.com/cyb3rops/status/1185459425710092288"
    score = 45
    threatname = "None"
    threattype = "None"
  strings:
    $a1 = "ReportIdentifier=" wide
    $a2 = ".Name=Fault Module Name" wide
    $s1 = "c0000374" wide /* Heap Corruption */
  condition:
    ( uint32be(0) == 0x56006500 or uint32be(0) == 0xfffe5600 )
    and all of them
}