rule PoisonIvy_Sample_APT {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-03"
    description = "Detects a PoisonIvy APT malware group"
    family = "None"
    hacker = "None"
    hash = "b874b76ff7b281c8baa80e4a71fc9be514093c70"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "VT Analysis"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "pidll.dll" fullword ascii /* score: '11.02' */
    $s1 = "sens32.dll" fullword wide /* score: '11.015' */
    $s3 = "FileDescription" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 19311 times */
    $s4 = "OriginalFilename" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 19040 times */
    $s5 = "ZwSetInformationProcess" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 31 times */
    $s9 = "Microsoft Media Device Service Provider" fullword wide /* score: '-3' */ /* Goodware String - occured 8 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 47KB and all of them
}