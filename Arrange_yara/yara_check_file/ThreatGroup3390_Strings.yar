rule ThreatGroup3390_Strings {
  meta:
    author = Spider
    comment = None
    date = 2015-08-06
    description = Threat Group 3390 APT - Strings
    family = None
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://snip.ly/giNB
    score = 60
    threatname = ThreatGroup3390[Strings
    threattype = Strings.yar
  strings:
    $s1 = "\"cmd\" /c cd /d \"c:\\Windows\\Temp\\\"&copy" ascii
    $s2 = "svchost.exe a -k -r -s -m5 -v1024000 -padmin-windows2014"
    $s3 = "ren *.rar *.zip" fullword ascii
    $s4 = "c:\\temp\\ipcan.exe" fullword ascii
    $s5 = "<%eval(Request.Item(\"admin-na-google123!@#" ascii
  condition:
    1 of them and filesize < 30KB
}