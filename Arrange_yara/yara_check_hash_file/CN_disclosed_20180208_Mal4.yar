rule CN_disclosed_20180208_Mal4 {
  meta:
    author = Spider
    comment = None
    date = 2018-02-08
    description = Detects malware from disclosed CN malware set
    family = Mal4
    hacker = None
    hash1 = f7549c74f09be7e4dbfb64006e535b9f6d17352e236edc2cdb102ec3035cf66e
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details
    threatname = CN[disclosed]/20180208.Mal4
    threattype = disclosed
  strings:
    $s1 = "Microsoft .Net Framework COM+ Support" fullword ascii
    $s2 = "Microsoft .NET and Windows XP COM+ Integration with SOAP" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them and pe.exports("SPACE")
}