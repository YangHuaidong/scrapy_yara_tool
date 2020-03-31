rule Fireball_gubed {
   meta:
      description = "Detects Fireball malware - file gubed.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/4pTkGQ"
      date = "2017-06-02"
      hash1 = "e3f69a1fb6fcaf9fd93386b6ba1d86731cd9e5648f7cff5242763188129cd158"
   strings:
      $x1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\MRT.exe" fullword wide
      $x2 = "tIphlpapi.dll" fullword wide
      $x3 = "http://%s/provide?clients=%s&reqs=visit.startload" fullword wide
      $x4 = "\\Gubed\\Release\\Gubed.pdb" fullword ascii
      $x5 = "d2hrpnfyb3wv3k.cloudfront.net" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}