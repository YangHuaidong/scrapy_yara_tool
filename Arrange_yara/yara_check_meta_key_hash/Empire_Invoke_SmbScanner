rule Empire_Invoke_SmbScanner {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-11-05"
    description = "Detects Empire component - file Invoke-SmbScanner.ps1"
    family = "None"
    hacker = "None"
    hash1 = "9a705f30766279d1e91273cfb1ce7156699177a109908e9a986cc2d38a7ab1dd"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/adaptivethreat/Empire"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$up = Test-Connection -count 1 -Quiet -ComputerName $Computer " fullword ascii
    $s2 = "$out | add-member Noteproperty 'Password' $Password" fullword ascii
  condition:
    ( uint16(0) == 0x7566 and filesize < 10KB and 1 of them ) or all of them
}