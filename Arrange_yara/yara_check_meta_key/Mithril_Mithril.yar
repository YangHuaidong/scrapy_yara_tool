rule Mithril_Mithril {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file Mithril.exe"
    family = "None"
    hacker = "None"
    hash = "017191562d72ab0ca551eb89256650bd"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "OpenProcess error!"
    $s1 = "WriteProcessMemory error!"
    $s4 = "GetProcAddress error!"
    $s5 = "HHt`HHt\\"
    $s6 = "Cmaudi0"
    $s7 = "CreateRemoteThread error!"
    $s8 = "Kernel32"
    $s9 = "VirtualAllocEx error!"
  condition:
    all of them
}