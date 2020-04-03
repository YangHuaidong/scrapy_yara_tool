rule Codoso_PGV_PVID_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-01-30"
    description = "Detects Codoso APT PGV PVID Malware"
    family = "None"
    hacker = "None"
    hash1 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
    hash2 = "b631553421aa17171cc47248adc110ca2e79eff44b5e5b0234d69b30cab104e3"
    hash3 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" fullword ascii
    $s1 = "regsvr32.exe /s \"%s\"" fullword ascii
    $s2 = "Help and Support" fullword ascii
    $s3 = "netsvcs" fullword ascii
    $s9 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" fullword ascii /* Goodware String - occured 4 times */
    $s10 = "winlogon" fullword ascii /* Goodware String - occured 4 times */
    $s11 = "System\\CurrentControlSet\\Services" fullword ascii /* Goodware String - occured 11 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 907KB and all of them
}