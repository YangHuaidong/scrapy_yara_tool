rule Crackmapexec_EXE {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-04-06"
    description = "Detects CrackMapExec hack tool"
    family = "None"
    hacker = "None"
    hash1 = "371f104b7876b9080c519510879235f36edb6668097de475949b84ab72ee9a9a"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "core.scripts.secretsdump(" fullword ascii
    $s2 = "core.scripts.samrdump(" fullword ascii
    $s3 = "core.uacdump(" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 10000KB and 2 of them
}