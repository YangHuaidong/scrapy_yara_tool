rule EquationGroup__ftshell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-08"
    description = "Equation Group hack tool leaked by ShadowBrokers- from files ftshell, ftshell.v3.10.3.7"
    family = "None"
    hacker = "None"
    hash1 = "9bebeb57f1c9254cb49976cc194da4be85da4eb94475cb8d813821fb0b24f893"
    hash4 = "0be739024b41144c3b63e40e46bab22ac098ccab44ab2e268efc3b63aea02951"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "if { [string length $uRemoteUploadCommand]" fullword ascii
    $s2 = "processUpload" fullword ascii
    $s3 = "global dothisreallyquiet" fullword ascii
  condition:
    ( uint16(0) == 0x2123 and filesize < 100KB and 2 of them ) or ( all of them )
}