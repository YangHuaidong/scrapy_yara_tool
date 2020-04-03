rule Empire_Invoke_BypassUAC {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-08-06"
    description = "Empire - a pure PowerShell post-exploitation agent - file Invoke-BypassUAC.ps1"
    family = "None"
    hacker = "None"
    hash = "ab0f900a6915b7497313977871a64c3658f3e6f73f11b03d2d33ca61305dc6a8"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/PowerShellEmpire/Empire"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory" fullword ascii
    $s2 = "$proc = Start-Process -WindowStyle Hidden notepad.exe -PassThru" fullword ascii
    $s3 = "$Payload = Invoke-PatchDll -DllBytes $Payload -FindString \"ExitThread\" -ReplaceString \"ExitProcess\"" fullword ascii
    $s4 = "$temp = [System.Text.Encoding]::UNICODE.GetBytes($szTempDllPath)" fullword ascii
  condition:
    filesize < 1200KB and 3 of them
}