rule DLL_Injector_Lynx {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-08-20"
    description = "Detects Lynx DLL Injector"
    family = "None"
    hacker = "None"
    hash1 = "d594f60e766e0c3261a599b385e3f686b159a992d19fa624fad8761776efa4f0"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = " -p <TARGET PROCESS NAME> | -u <DLL PAYLOAD> [--obfuscate]" fullword wide
    $x2 = "You've selected to inject into process: %s" fullword wide
    $x3 = "Lynx DLL Injector" fullword wide
    $x4 = "Reflective DLL Injector" fullword wide
    $x5 = "Failed write payload: %lu" fullword wide
    $x6 = "Failed to start payload: %lu" fullword wide
    $x7 = "Injecting payload..." fullword wide
  condition:
    ( uint16(0) == 0x5a4d and
    filesize < 800KB and
    1 of them
    ) or ( 3 of them )
}