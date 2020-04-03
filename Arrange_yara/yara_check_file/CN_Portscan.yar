rule CN_Portscan : APT
{
    meta:
        description = "CN Port Scanner"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        date = "2013-11-29"
        confidential = false
      score = 70
    strings:
      $s2 = "TCP 12.12.12.12"
    condition:
        uint16(0) == 0x5A4D and $s2
}