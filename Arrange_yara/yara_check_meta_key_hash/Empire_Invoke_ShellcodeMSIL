rule Empire_Invoke_ShellcodeMSIL {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-11-05"
    description = "Detects Empire component - file Invoke-ShellcodeMSIL.ps1"
    family = "None"
    hacker = "None"
    hash1 = "9a9c6c9eb67bde4a8ce2c0858e353e19627b17ee2a7215fa04a19010d3ef153f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/adaptivethreat/Empire"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$FinalShellcode.Length" fullword ascii
    $s2 = "@(0x60,0xE8,0x04,0,0,0,0x61,0x31,0xC0,0xC3)" fullword ascii
    $s3 = "@(0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57," fullword ascii
    $s4 = "$TargetMethod.Invoke($null, @(0x11112222)) | Out-Null" fullword ascii
  condition:
    ( uint16(0) == 0x7566 and filesize < 30KB and 1 of them ) or all of them
}