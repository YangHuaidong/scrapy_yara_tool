rule x_way2_5_sqlcmd {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file sqlcmd.exe"
    family = "None"
    hacker = "None"
    hash = "5152a57e3638418b0d97a42db1c0fc2f893a2794"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "LOADER ERROR" fullword ascii
    $s2 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
    $s3 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
    $s4 = "kernel32.dll" fullword ascii
    $s5 = "VirtualAlloc" fullword ascii
    $s6 = "VirtualFree" fullword ascii
    $s7 = "VirtualProtect" fullword ascii
    $s8 = "ExitProcess" fullword ascii
    $s9 = "user32.dll" fullword ascii
    $s16 = "MessageBoxA" fullword ascii
    $s10 = "wsprintfA" fullword ascii
    $s11 = "kernel32.dll" fullword ascii
    $s12 = "GetProcAddress" fullword ascii
    $s13 = "GetModuleHandleA" fullword ascii
    $s14 = "LoadLibraryA" fullword ascii
    $s15 = "odbc32.dll" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 23KB and filesize > 20KB and all of them
}