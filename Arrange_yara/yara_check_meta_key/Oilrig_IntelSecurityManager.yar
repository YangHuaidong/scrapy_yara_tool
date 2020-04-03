rule Oilrig_IntelSecurityManager {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-01-19"
    description = "Detects OilRig malware"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $one1 = "srvResesponded" ascii wide fullword
    $one2 = "InetlSecurityAssistManager" ascii wide fullword
    $one3 = "srvCheckresponded" ascii wide fullword
    $one4 = "IntelSecurityManager" ascii wide
    $one5 = "msoffice365cdn.com" ascii wide
    $one6 = "\\tmpCa.vbs" ascii wide
    $one7 = "AAZFinish" ascii wide fullword
    $one8 = "AAZUploaded" ascii wide fullword
    $one9 = "ABZFinish" ascii wide fullword
    $one10 = "\\tmpCa.vbs" ascii wide
  condition:
    filesize < 300KB and any of them
}