rule Win_PrivEsc_ADACLScan4_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-06-02"
    description = "Detects a tool that can be used for privilege escalation - file ADACLScan4.3.ps1"
    family = "None"
    hacker = "None"
    hash1 = "3473ddb452de7640fab03cad3e8aaf6a527bdd6a7a311909cfef9de0b4b78333"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://adaclscan.codeplex.com/"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<Label x:Name=\"lblPort\" Content=\"Port:\"  HorizontalAlignment=\"Left\" Height=\"28\" Margin=\"10,0,0,0\" Width=\"35\"/>" fullword ascii
    $s2 = "(([System.IconExtractor]::Extract(\"mmcndmgr.dll\", 126, $true)).ToBitMap()).Save($env:temp + \"\\Other.png\")    " fullword ascii
    $s3 = "$bolValid = $ctx.ValidateCredentials($psCred.UserName,$psCred.GetNetworkCredential().Password)" fullword ascii
  condition:
    all of them
}