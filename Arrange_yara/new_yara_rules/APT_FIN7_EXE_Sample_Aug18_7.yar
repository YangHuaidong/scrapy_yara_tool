rule APT_FIN7_EXE_Sample_Aug18_7 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-08-01"
    description = "Detects sample from FIN7 report in August 2018"
    family = "None"
    hacker = "None"
    hash1 = "ce8ce35f85406cd7241c6cc402431445fa1b5a55c548cca2ea30eeb4a423b6f0"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "libpng version" fullword ascii
    $s2 = "sdfkjdfjfhgurgvncmnvmfdjdkfjdkfjdf" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 800KB and all of them
}