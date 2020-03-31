rule SUSP_RTF_Header_Anomaly {
  meta:
    author = Spider
    comment = None
    date = 2019-01-20
    description = Detects malformed RTF header often used to trick mechanisms that check for a full RTF header
    family = Anomaly
    hacker = None
    judge = unknown
    reference = https://twitter.com/ItsReallyNick/status/975705759618158593
    threatname = SUSP[RTF]/Header.Anomaly
    threattype = RTF
  condition:
    uint32(0) == 0x74725c7b and /* {\rt */
    not uint8(4) == 0x66 /* not f */
}