rule SUSP_RTF_Header_Anomaly {
   meta:
      description = "Detects malformed RTF header often used to trick mechanisms that check for a full RTF header"
      author = "Florian Roth"
      reference = "https://twitter.com/ItsReallyNick/status/975705759618158593"
      date = "2019-01-20"
   condition:
      uint32(0) == 0x74725c7b and /* {\rt */
      not uint8(4) == 0x66 /* not f */
}