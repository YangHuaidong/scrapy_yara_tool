rule Empire_Get_GPPPassword {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-11-05"
    description = "Detects Empire component - file Get-GPPPassword.ps1"
    family = "None"
    hacker = "None"
    hash1 = "55a4519c4f243148a971e4860225532a7ce730b3045bde3928303983ebcc38b0"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/adaptivethreat/Empire"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$Base64Decoded = [Convert]::FromBase64String($Cpassword)" fullword ascii
    $s2 = "$XMlFiles += Get-ChildItem -Path \"\\\\$DomainController\\SYSVOL\" -Recurse" ascii
    $s3 = "function Get-DecryptedCpassword {" fullword ascii
  condition:
    ( uint16(0) == 0x7566 and filesize < 30KB and 1 of them ) or all of them
}