rule PoisonIvy_Sample_7 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-03"
    description = "Detects PoisonIvy RAT sample set"
    family = "None"
    hacker = "None"
    hash = "9480cf544beeeb63ffd07442233eb5c5f0cf03b3"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "VT Analysis"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Microsoft Software installation Service" fullword wide /* PEStudio Blacklist: strings */ /* score: '15.04' */
    $s2 = "pidll.dll" fullword ascii /* score: '11.02' */
    $s10 = "ServiceMain" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 322 times */
    $s11 = "ZwSetInformationProcess" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 31 times */
    $s12 = "Software installation Service" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 3 times */
    $s13 = "Microsoft(R) Windows(R) Operating System" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 128 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and all of them
}