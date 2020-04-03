import "pe"
rule ReflectiveLoader {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Detects a unspecified hack tool, crack or malware using a reflective loader - no hard match - further investigation recommended"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "Internal Research"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "ReflectiveLoader" fullword ascii
    $s2 = "ReflectivLoader.dll" fullword ascii
    $s3 = "?ReflectiveLoader@@" ascii
  condition:
    uint16(0) == 0x5a4d and (
    1 of them or
    pe.exports("ReflectiveLoader") or
    pe.exports("_ReflectiveLoader@4") or
    pe.exports("?ReflectiveLoader@@YGKPAX@Z")
}