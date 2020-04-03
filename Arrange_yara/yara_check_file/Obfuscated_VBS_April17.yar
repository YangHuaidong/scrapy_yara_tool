rule Obfuscated_VBS_April17 {
   meta:
      description = "Detects cloaked Mimikatz in VBS obfuscation"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-04-21"
   strings:
      $s1 = "::::::ExecuteGlobal unescape(unescape(" ascii
   condition:
      filesize < 500KB and all of them
}