rule HKTL_NoPowerShell {
   meta:
      description = "Detects NoPowerShell hack tool"
      author = "Florian Roth"
      reference = "https://github.com/bitsadmin/nopowershell"
      date = "2018-12-28"
      hash1 = "2dad091dd00625762a7590ce16c3492cbaeb756ad0e31352a42751deb7cf9e70"
   strings:
      $x1 = "\\NoPowerShell.pdb" fullword ascii
      $x2 = "Invoke-WmiMethod -Class Win32_Process -Name Create \"cmd" fullword wide
      $x3 = "ls C:\\Windows\\System32 -Include *.exe | select -First 10 Name,Length" fullword wide
      $x4 = "ls -Recurse -Force C:\\Users\\ -Include *.kdbx" fullword wide
      $x5 = "NoPowerShell.exe" fullword wide
   condition:
      1 of them
}