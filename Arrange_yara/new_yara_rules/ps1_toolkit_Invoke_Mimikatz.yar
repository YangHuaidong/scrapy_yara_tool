rule ps1_toolkit_Invoke_Mimikatz {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-09-04"
    description = "Auto-generated rule - file Invoke-Mimikatz.ps1"
    family = "None"
    hacker = "None"
    hash1 = "5c31a2e3887662467cfcb0ac37e681f1d9b0f135e6dfff010aae26587e03d8c8"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/vysec/ps1-toolkit"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Get-ProcAddress kernel32.dll WriteProcessMemory" fullword ascii
    $s2 = "ps | where { $_.Name -eq $ProcName } | select ProcessName, Id, SessionId" fullword ascii
    $s3 = "privilege::debug exit" ascii
    $s4 = "Get-ProcAddress Advapi32.dll AdjustTokenPrivileges" fullword ascii
    $s5 = "Invoke-Mimikatz -DumpCreds" fullword ascii
    $s6 = "| Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002" fullword ascii
  condition:
    ( uint16(0) == 0xbbef and filesize < 10000KB and 1 of them ) or ( 3 of them )
}