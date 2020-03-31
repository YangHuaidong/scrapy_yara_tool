rule BadRabbit_Mimikatz_Comp {
   meta:
      description = "Auto-generated rule - file 2f8c54f9fa8e47596a3beff0031f85360e56840c77f71c6a573ace6f46412035"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://pastebin.com/Y7pJv3tK"
      date = "2017-10-25"
      hash1 = "2f8c54f9fa8e47596a3beff0031f85360e56840c77f71c6a573ace6f46412035"
   strings:
      $s1 = "%lS%lS%lS:%lS" fullword wide
      $s2 = "lsasrv" fullword wide
      $s3 = "CredentialKeys" ascii
      /* Primary\x00m\x00s\x00v */
      $s4 = { 50 72 69 6D 61 72 79 00 6D 00 73 00 76 00 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 3 of them )
}