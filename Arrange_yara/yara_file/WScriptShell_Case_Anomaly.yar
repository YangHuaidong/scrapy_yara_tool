rule WScriptShell_Case_Anomaly {
   meta:
      description = "Detects obfuscated wscript.shell commands"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-09-11"
      score = 60
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