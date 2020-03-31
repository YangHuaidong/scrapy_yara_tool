rule Empire_Invoke_SmbScanner {
   meta:
      description = "Detects Empire component - file Invoke-SmbScanner.ps1"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "9a705f30766279d1e91273cfb1ce7156699177a109908e9a986cc2d38a7ab1dd"
   strings:
      $s1 = "$up = Test-Connection -count 1 -Quiet -ComputerName $Computer " fullword ascii
      $s2 = "$out | add-member Noteproperty 'Password' $Password" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 10KB and 1 of them ) or all of them
}