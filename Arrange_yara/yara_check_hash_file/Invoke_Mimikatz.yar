rule Invoke_Mimikatz {
  meta:
    author = Spider
    comment = None
    date = 2016-08-03
    description = Detects Invoke-Mimikatz String
    family = None
    hacker = None
    hash1 = f1a499c23305684b9b1310760b19885a472374a286e2f371596ab66b77f6ab67
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://github.com/clymb3r/PowerShell/tree/master/Invoke-Mimikatz
    threatname = Invoke[Mimikatz
    threattype = Mimikatz.yar
  strings:
    $x2 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm" ascii
    $x3 = "Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp" fullword ascii
  condition:
    1 of them
}