rule Destructive_Ransomware_Gen1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-02-12"
    description = "Detects destructive malware"
    family = "None"
    hacker = "None"
    hash1 = "ae9a4e244a9b3c77d489dee8aeaf35a7c3ba31b210e76d81ef2e91790f052c85"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://blog.talosintelligence.com/2018/02/olympic-destroyer.html"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "/set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no" fullword wide
    $x2 = "delete shadows /all /quiet" fullword wide
    $x3 = "delete catalog -quiet" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}