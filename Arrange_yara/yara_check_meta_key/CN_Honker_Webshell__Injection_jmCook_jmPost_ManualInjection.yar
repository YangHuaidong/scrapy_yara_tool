rule CN_Honker_Webshell__Injection_jmCook_jmPost_ManualInjection {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - from files Injection.exe, jmCook.asp, jmPost.asp, ManualInjection.exe"
    family = "None"
    hacker = "None"
    hash0 = "3484ed16e6f9e0d603cbc5cb44e46b8b7e775d35"
    hash1 = "5e1851c77ce922e682333a3cb83b8506e1d7395d"
    hash2 = "f80ec26bbdc803786925e8e0450ad7146b2478ff"
    hash3 = "e83d427f44783088a84e9c231c6816c214434526"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "response.write  PostData(JMUrl,JmStr,JmCok,JmRef)" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "strReturn=Replace(strReturn,chr(43),\"%2B\")  'JMDCW" fullword ascii
  condition:
    filesize < 7342KB and all of them
}