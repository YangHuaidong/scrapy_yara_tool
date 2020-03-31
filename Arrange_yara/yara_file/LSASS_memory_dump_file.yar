rule LSASS_memory_dump_file {
   meta:
      description = "Detects a LSASS memory dump file"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      date = "2015/03/31"
      memory = 0
      score = 50
   strings:
      $s1 = "lsass.exe" ascii fullword
      $s2 = "wdigest.DLL" wide nocase
   condition:
        uint32(0) == 0x504D444D and all of them
}