rule Empire_KeePassConfig {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-11-05"
    description = "Detects Empire component - file KeePassConfig.ps1"
    family = "None"
    hacker = "None"
    hash1 = "5a76e642357792bb4270114d7cd76ce45ba24b0d741f5c6b916aeebd45cff2b3"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/adaptivethreat/Empire"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$UserMasterKeyFiles = @(, $(Get-ChildItem -Path $UserMasterKeyFolder -Force | Select-Object -ExpandProperty FullName) )" fullword ascii
  condition:
    ( uint16(0) == 0x7223 and filesize < 80KB and 1 of them ) or all of them
}