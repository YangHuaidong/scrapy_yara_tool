rule FIN7_Dropper_Aug17 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-08-04"
    description = "Detects Word Dropper from Proofpoint FIN7 Report"
    family = "None"
    hacker = "None"
    hash1 = "c91642c0a5a8781fff9fd400bff85b6715c96d8e17e2d2390c1771c683c7ead9"
    hash2 = "cf86c7a92451dca1ebb76ebd3e469f3fa0d9b376487ee6d07ae57ab1b65a86f8"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.proofpoint.com/us/threat-insight/post/fin7carbanak-threat-actor-unleashes-bateleur-jscript-backdoor"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "tpircsj:e/ b// exe.tpircsw\" rt/" fullword ascii
    $s1 = "Scripting.FileSystemObject$" fullword ascii
    $s2 = "PROJECT.THISDOCUMENT.AUTOOPEN" fullword wide
    $s3 = "Project.ThisDocument.AutoOpen" fullword wide
    $s4 = "\\system3" fullword ascii
    $s5 = "ShellV" fullword ascii
  condition:
    ( uint16(0) == 0xcfd0 and filesize < 700KB and 1 of ($x*) or all of ($s*) )
}