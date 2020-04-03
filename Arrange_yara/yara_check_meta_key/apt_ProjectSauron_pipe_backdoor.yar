rule apt_ProjectSauron_pipe_backdoor {
  meta:
    author = "Spider"
    comment = "None"
    copyright = "Kaspersky Lab"
    date = "None"
    description = "Rule to detect ProjectSauron pipe backdoors"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://securelist.com/blog/"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $a1 = "CreateNamedPipeW" fullword ascii
    $a2 = "SetSecurityDescriptorDacl" fullword ascii
    $a3 = "GetOverlappedResult" fullword ascii
    $a4 = "TerminateThread" fullword ascii
    $a5 = "%s%s%X" fullword wide
  condition:
    uint16(0) == 0x5A4D
    and (all of ($a*))
    and filesize < 100000
}