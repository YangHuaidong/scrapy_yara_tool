rule Apolmy_Privesc_Trojan {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-08-04"
    description = "Apolmy Privilege Escalation Trojan used in APT Terracotta"
    family = "None"
    hacker = "None"
    hash = "d7bd289e6cee228eb46a1be1fcdc3a2bd5251bc1eafb59f8111756777d8f373d"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "[%d] Failed, %08X" fullword ascii
    $s2 = "[%d] Offset can not fetched." fullword ascii
    $s3 = "PowerShadow2011" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and all of them
}