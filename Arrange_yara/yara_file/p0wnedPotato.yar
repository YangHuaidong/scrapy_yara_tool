rule p0wnedPotato {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedPotato.cs"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "aff2b694a01b48ef96c82daf387b25845abbe01073b76316f1aab3142fdb235b"
   strings:
      $x1 = "Invoke-Tater" fullword ascii
      $x2 = "P0wnedListener.Execute(WPAD_Proxy);" fullword ascii
      $x3 = " -SpooferIP " ascii
      $x4 = "TaterCommand()" ascii
      $x5 = "FileName = \"cmd.exe\"," fullword ascii
   condition:
      1 of them
}