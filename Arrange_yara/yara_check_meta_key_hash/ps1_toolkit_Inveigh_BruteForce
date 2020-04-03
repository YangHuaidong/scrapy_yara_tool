rule ps1_toolkit_Inveigh_BruteForce {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-09-04"
    description = "Auto-generated rule - file Inveigh-BruteForce.ps1"
    family = "None"
    hacker = "None"
    hash1 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/vysec/ps1-toolkit"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Import-Module .\\Inveigh.psd1;Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 " fullword ascii
    $s2 = "$(Get-Date -format 's') - Attempting to stop HTTP listener\")|Out-Null" fullword ascii
    $s3 = "Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 -Hostname server1" fullword ascii
  condition:
    ( uint16(0) == 0xbbef and filesize < 300KB and 1 of them ) or ( 2 of them )
}