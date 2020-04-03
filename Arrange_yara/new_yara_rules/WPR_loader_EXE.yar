rule WPR_loader_EXE {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-03-15"
    description = "Windows Password Recovery - file loader.exe"
    family = "None"
    hacker = "None"
    hash1 = "e7d158d27d9c14a4f15a52ee5bf8aa411b35ad510b1b93f5e163ae7819c621e2"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Failed to get system process ID" fullword wide
    $s2 = "gLSASS.EXE" fullword wide
    $s3 = "WriteProcessMemory failed" fullword wide
    $s4 = "wow64 process NOT created" fullword wide
    $s5 = "\\ast.exe" fullword wide
    $s6 = "Exit code=%s, status=%d" fullword wide
    $s7 = "VirtualProtect failed" fullword wide
    $s8 = "nSeDebugPrivilege" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 100KB and 3 of them )
}