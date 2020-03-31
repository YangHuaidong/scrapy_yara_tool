rule TeleBots_KillDisk_2 {
   meta:
      description = "Detects TeleBots malware - KillDisk"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/4if3HG"
      date = "2016-12-14"
      hash1 = "26173c9ec8fd1c4f9f18f89683b23267f6f9d116196ed15655e9cb453af2890e"
   strings:
      $s1 = "Plug-And-Play Support Service" fullword wide
      $s2 = " /c \"echo Y|" fullword wide
      $s3 = "%d.%d.%d#%d:%d" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and all of them )
}