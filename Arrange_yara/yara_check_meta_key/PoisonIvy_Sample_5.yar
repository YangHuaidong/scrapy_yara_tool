rule PoisonIvy_Sample_5 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-03"
    description = "Detects PoisonIvy RAT sample set"
    family = "None"
    hacker = "None"
    hash = "545e261b3b00d116a1d69201ece8ca78d9704eb2"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "VT Analysis"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Microsoft Software installation Service" fullword wide /* PEStudio Blacklist: strings */ /* score: '15.04' */
    $s2 = "pidll.dll" fullword ascii /* score: '11.02' */
    $s3 = "\\mspmsnsv.dll" fullword ascii /* score: '11.005' */
    $s4 = "\\sfc.exe" fullword ascii /* score: '11.005' */
    $s13 = "ServiceMain" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 322 times */
    $s15 = "ZwSetInformationProcess" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 31 times */
    $s17 = "LookupPrivilegeValueA" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 336 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and all of them
}