rule Turla_APT_srsvc {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-06-09"
    description = "Detects Turla malware (based on sample used in the RUAG APT case)"
    family = "Turla"
    hacker = "None"
    hash1 = "65996f266166dbb479a42a15a236e6564f0b322d5d68ee546244d7740a21b8f7"
    hash2 = "25c7ff1eb16984a741948f2ec675ab122869b6edea3691b01d69842a53aa3bac"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.govcert.admin.ch/blog/22/technical-report-about-the-ruag-espionage-case"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "SVCHostServiceDll.dll" fullword ascii
    $s2 = "msimghlp.dll" fullword wide
    $s3 = "srservice" fullword wide
    $s4 = "ModStart" fullword ascii
    $s5 = "ModStop" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 20KB and ( 1 of ($x*) or all of ($s*) ) )
    or ( all of them )
}