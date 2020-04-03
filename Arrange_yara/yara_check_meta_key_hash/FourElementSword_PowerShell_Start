rule FourElementSword_PowerShell_Start {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-04-18"
    description = "Detects FourElementSword Malware - file 9b6053e784c5762fdb9931f9064ba6e52c26c2d4b09efd6ff13ca87bbb33c692"
    family = "None"
    hacker = "None"
    hash = "9b6053e784c5762fdb9931f9064ba6e52c26c2d4b09efd6ff13ca87bbb33c692"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "start /min powershell C:\\\\ProgramData\\\\wget.exe" ascii
    $s1 = "start /min powershell C:\\\\ProgramData\\\\iuso.exe" fullword ascii
  condition:
    1 of them
}