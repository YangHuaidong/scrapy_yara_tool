rule KeeThief_PS {
   meta:
      description = "Detects component of KeeTheft - KeePass dump tool - file KeeThief.ps1"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/HarmJ0y/KeeThief"
      date = "2017-08-29"
      hash1 = "a3b976279ded8e64b548c1d487212b46b03aaec02cb6e199ea620bd04b8de42f"
   strings:
      $x1 = "$WMIProcess = Get-WmiObject win32_process -Filter \"ProcessID = $($KeePassProcess.ID)\"" fullword ascii
      $x2 = "if($KeePassProcess.FileVersion -match '^2\\.') {" fullword ascii
   condition:
      ( uint16(0) == 0x7223 and
        filesize < 1000KB and
        ( 1 of ($x*) )
      )
}