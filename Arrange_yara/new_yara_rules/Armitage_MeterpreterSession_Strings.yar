rule Armitage_MeterpreterSession_Strings {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-12-24"
    description = "Detects Armitage component"
    family = "None"
    hacker = "None"
    hash1 = "b258b2f12f57ed05d8eafd29e9ecc126ae301ead9944a616b87c240bf1e71f9a"
    hash2 = "144cb6b1cf52e60f16b45ddf1633132c75de393c2705773b9f67fce334a3c8b8"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "session.meterpreter_read" fullword ascii
    $s2 = "sniffer_dump" fullword ascii
    $s3 = "keyscan_dump" fullword ascii
    $s4 = "mimikatz_command" fullword ascii
    $s5 = "MeterpreterSession.java" fullword ascii
  condition:
    filesize < 30KB and 1 of them
}