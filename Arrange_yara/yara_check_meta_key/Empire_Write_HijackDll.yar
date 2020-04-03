rule Empire_Write_HijackDll {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-08-06"
    description = "Empire - a pure PowerShell post-exploitation agent - file Write-HijackDll.ps1"
    family = "None"
    hacker = "None"
    hash = "155fa7168e28f15bb34f67344f47234a866e2c63b3303422ff977540623c70bf"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/PowerShellEmpire/Empire"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$DllBytes = Invoke-PatchDll -DllBytes $DllBytes -FindString \"debug.bat\" -ReplaceString $BatchPath" fullword ascii
    $s2 = "$DllBytes32 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4AAAAA4fug4AtAnNIbgBTM0hVGhpcyBw" ascii
    $s3 = "[Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes32)" fullword ascii
  condition:
    filesize < 500KB and 2 of them
}