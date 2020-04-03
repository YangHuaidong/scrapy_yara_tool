rule WScriptShell_Case_Anomaly {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-09-11"
    description = "Detects obfuscated wscript.shell commands"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "WScript.Shell\").Run" nocase ascii wide
    $sn1 = "WScript.Shell\").Run" ascii wide
    $sn2 = "wscript.shell\").run" ascii wide
    $sn3 = "WSCRIPT.SHELL\").RUN" ascii wide
    $sn4 = "Wscript.Shell\").Run" ascii wide
    $sn5 = "WScript.Shell\").Run" ascii wide
    $sn6 = "WScript.shell\").Run" ascii wide
  condition:
    filesize < 800KB and
    ( $s1 and not 1 of ($sn*) )
}