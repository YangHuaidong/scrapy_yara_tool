rule APT_Lazarus_Aug18_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-08-24"
    description = "Detects Lazarus Group Malware"
    family = "None"
    hacker = "None"
    hash1 = "8ae766795cda6336fd5cad9e89199ea2a1939a35e03eb0e54c503b1029d870c4"
    hash2 = "d3ef262bae0beb5d35841d131b3f89a9b71a941a86dab1913bda72b935744d2e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://securelist.com/operation-applejeus/87553/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "vAdvapi32.dll" fullword wide
    $s2 = "lws2_32.dll" fullword wide
    $s3 = "%s %s > \"%s\" 2>&1" fullword wide
    $s4 = "Not Service" fullword wide
    $s5 = "ping 127.0.0.1 -n 3" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 600KB and (
    4 of them
}