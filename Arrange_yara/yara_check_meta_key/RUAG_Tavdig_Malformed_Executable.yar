rule RUAG_Tavdig_Malformed_Executable {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Detects an embedded executable with a malformed header - known from Tavdig malware"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://goo.gl/N5MEj0"
    score = 60
    threatname = "None"
    threattype = "None"
  condition:
    uint16(0) == 0x5a4d and /* MZ Header */
    uint32(uint32(0x3C)) == 0x0000AD0B /* malformed PE header > 0x0bad */
}