rule Fireball_winsap {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-06-02"
    description = "Detects Fireball malware - file winsap.dll"
    family = "None"
    hacker = "None"
    hash1 = "c7244d139ef9ea431a5b9cc6a2176a6a9908710892c74e215431b99cd5228359"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/4pTkGQ"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "aHR0cDovL2" ascii /* base64 encoded string 'http://d3i1asoswufp5k.cloudfront.net/v4/gtg/%s?action=visit.winsap.work&update3=version,%s' */
    $s2 = "%s\\svchost.exe -k %s" fullword wide
    $s3 = "\\SETUP.dll" fullword wide
    $s4 = "WinSAP.dll" fullword ascii
    $s5 = "Error %u in WinHttpQueryDataAvailable." fullword ascii
    $s6 = "UPDATE OVERWRITE" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 600KB and 4 of them )
}