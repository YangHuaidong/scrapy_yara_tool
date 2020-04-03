rule p0wnedPotato {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-14"
    description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedPotato.cs"
    family = "None"
    hacker = "None"
    hash1 = "aff2b694a01b48ef96c82daf387b25845abbe01073b76316f1aab3142fdb235b"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/Cn33liz/p0wnedShell"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Invoke-Tater" fullword ascii
    $x2 = "P0wnedListener.Execute(WPAD_Proxy);" fullword ascii
    $x3 = " -SpooferIP " ascii
    $x4 = "TaterCommand()" ascii
    $x5 = "FileName = \"cmd.exe\"," fullword ascii
  condition:
    1 of them
}