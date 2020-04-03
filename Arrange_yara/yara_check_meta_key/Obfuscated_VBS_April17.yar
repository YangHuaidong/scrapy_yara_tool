rule Obfuscated_VBS_April17 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-21"
    description = "Detects cloaked Mimikatz in VBS obfuscation"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "::::::ExecuteGlobal unescape(unescape(" ascii
  condition:
    filesize < 500KB and all of them
}