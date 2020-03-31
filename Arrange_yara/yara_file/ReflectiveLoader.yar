rule ReflectiveLoader {
   meta:
      description = "Detects a unspecified hack tool, crack or malware using a reflective loader - no hard match - further investigation recommended"
      reference = "Internal Research"
      score = 60
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
         )
}