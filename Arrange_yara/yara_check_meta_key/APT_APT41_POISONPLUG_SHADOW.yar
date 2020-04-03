import "pe"
rule APT_APT41_POISONPLUG_SHADOW {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-08-07"
    description = "Detects APT41 malware POISONPLUG SHADOW"
    family = "None"
    hacker = "None"
    hash1 = "462a02a8094e833fd456baf0a6d4e18bb7dab1a9f74d5f163a8334921a4ffde8"
    judge = "black"
    reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
    score = 85
    threatname = "None"
    threattype = "None"
  condition:
    uint16(0) == 0x5a4d and filesize < 500KB and pe.imphash() == "c67de089f2009b21715744762fc484e8"
}