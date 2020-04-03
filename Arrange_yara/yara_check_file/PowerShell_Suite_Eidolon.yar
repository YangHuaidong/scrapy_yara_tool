rule PowerShell_Suite_Eidolon {
   meta:
      description = "Detects PowerShell Suite Eidolon script - file Start-Eidolon.ps1"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/FuzzySecurity/PowerShell-Suite"
      date = "2017-12-27"
      hash1 = "db31367410d0a9ffc9ed37f423a4b082639591be7f46aca91f5be261b23212d5"
   strings:
      $ = "[+] Eidolon entry point:" ascii
      $ = "C:\\PS> Start-Eidolon -Target C:\\Some\\File.Path -Mimikatz -Verbose" fullword ascii
      $ = "[Int16]$PEArch = '0x{0}' -f ((($PayloadBytes[($OptOffset+1)..($OptOffset)]) | % {$_.ToString('X2')}) -join '')" fullword ascii
   condition:
      uint16(0) == 0x7566 and filesize < 13000KB and 1 of them
}