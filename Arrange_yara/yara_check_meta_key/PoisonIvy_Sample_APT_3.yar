rule PoisonIvy_Sample_APT_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-03"
    description = "Detects a PoisonIvy Malware"
    family = "None"
    hacker = "None"
    hash = "df3e1668ac20edecc12f2c1a873667ea1a6c3d6a"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "VT Analysis"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "\\notepad.exe" fullword ascii /* score: '11.025' */
    $s1 = "\\RasAuto.dll" fullword ascii /* score: '11.025' */
    $s3 = "winlogon.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 13 times */
  condition:
    uint16(0) == 0x5a4d and all of them
}