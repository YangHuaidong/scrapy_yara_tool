rule CN_Toolset__XScanLib_XScanLib_XScanLib {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/30"
    description = "Detects a Chinese hacktool from a disclosed toolset - from files XScanLib.dll, XScanLib.dll, XScanLib.dll"
    family = "None"
    hacker = "None"
    hash0 = "af419603ac28257134e39683419966ab3d600ed2"
    hash1 = "c5cb4f75cf241f5a9aea324783193433a42a13b0"
    hash2 = "135f6a28e958c8f6a275d8677cfa7cb502c8a822"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://qiannao.com/ls/905300366/33834c0c/"
    score = 70
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Plug-in thread causes an exception, failed to alert user." fullword
    $s2 = "PlugGetUdpPort" fullword
    $s3 = "XScanLib.dll" fullword
    $s4 = "PlugGetTcpPort" fullword
    $s11 = "PlugGetVulnNum" fullword
  condition:
    all of them
}