rule Msfpayloads_msf_8 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-09"
    description = "Metasploit Payloads - file msf.ps1"
    family = "None"
    hacker = "None"
    hash1 = "519717e01f0cb3f460ef88cd70c3de8c7f00fb7c564260bd2908e97d11fde87f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "[DllImport(\"kernel32.dll\")]" fullword ascii
    $s2 = "[DllImport(\"msvcrt.dll\")]" fullword ascii
    $s3 = "-Name \"Win32\" -namespace Win32Functions -passthru" fullword ascii
    $s4 = "::VirtualAlloc(0,[Math]::Max($" ascii
    $s5 = ".Length,0x1000),0x3000,0x40)" ascii
    $s6 = "public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);" fullword ascii
    $s7 = "::memset([IntPtr]($" ascii
  condition:
    6 of them
}