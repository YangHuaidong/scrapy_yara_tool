rule Disclosed_0day_POCs_InjectDll {
   meta:
      description = "Detects POC code from disclosed 0day hacktool set"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Disclosed 0day Repos"
      date = "2017-07-07"
      hash1 = "173d3f78c9269f44d069afbd04a692f5ae42d5fdc9f44f074599ec91e8a29aa2"
   strings:
      $x1 = "\\Release\\InjectDll.pdb" fullword ascii
      $x2 = "Specify -l to list all IE processes running in the current session" fullword ascii
      $x3 = "Usage: InjectDll -l|pid PathToDll" fullword ascii
      $x4 = "Injecting DLL: %ls into PID: %d" fullword ascii
      $x5 = "Error adjusting privilege %d" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}