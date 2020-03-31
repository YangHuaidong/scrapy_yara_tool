rule CN_Portscan : APT {
  meta:
    author = Spider
    comment = None
    confidential = false
    date = 2013-11-29
    description = CN Port Scanner
    family = None
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = CN[Portscan
    threattype = Portscan.yar
  strings:
    $s2 = "TCP 12.12.12.12"
  condition:
    uint16(0) == 0x5A4D and $s2
}