rule EquationDrug_Keylogger {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/11"
    description = "EquationDrug - Key/clipboard logger driver - msrtvd.sys"
    family = "None"
    hacker = "None"
    hash = "b93aa17b19575a6e4962d224c5801fb78e9a7bb5"
    judge = "unknown"
    reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "\\registry\\machine\\software\\Microsoft\\Windows NT\\CurrentVersion" fullword wide
    $s2 = "\\registry\\machine\\SYSTEM\\ControlSet001\\Control\\Session Manager\\En" wide
    $s3 = "\\DosDevices\\Gk" fullword wide
    $s5 = "\\Device\\Gk0" fullword wide
  condition:
    all of them
}