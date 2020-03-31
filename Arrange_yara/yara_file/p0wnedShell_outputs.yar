rule p0wnedShell_outputs {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - from files p0wnedShell.cs, p0wnedShell.cs"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      super_rule = 1
      hash1 = "e1f35310192416cd79e60dba0521fc6eb107f3e65741c344832c46e9b4085e60"
   strings:
      $s1 = "[+] For this attack to succeed, you need to have Admin privileges." fullword ascii
      $s2 = "[+] This is not a valid hostname, please try again" fullword ascii
      $s3 = "[+] First return the name of our current domain." fullword ascii
   condition:
      1 of them
}