rule power_pe_injection {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PowerShell with PE Reflective Injection"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $str_loadlib = "0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9"
  condition:
    $str_loadlib
}