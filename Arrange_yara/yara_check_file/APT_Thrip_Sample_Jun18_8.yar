rule APT_Thrip_Sample_Jun18_8 {
  meta:
    author = Spider
    comment = None
    date = 2018-06-21
    description = Detects sample found in Thrip report by Symantec 
    family = Jun18
    hacker = None
    hash1 = 0f2d09b1ad0694f9e71eeebec5b2d137665375bf1e76cb4ae4d7f20487394ed3
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets 
    threatname = APT[Thrip]/Sample.Jun18.8
    threattype = Thrip
  strings:
    $x1 = "$.oS.Run('cmd.exe /c '+a+'" fullword ascii
    $x2 = "new $._x('WScript.Shell');" ascii
    $x3 = ".ExpandEnvironmentStrings('%Temp%')+unescape('" ascii
  condition:
    filesize < 10KB and 1 of ($x*)
}