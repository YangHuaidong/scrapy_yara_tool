rule iKAT_revelations {
   meta:
      description = "iKAT hack tool showing the content of password fields - file revelations.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      date = "05.11.14"
      score = 75
      reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
      hash = "c4e217a8f2a2433297961561c5926cbd522f7996"
   strings:
      $s0 = "The RevelationHelper.DLL file is corrupt or missing." fullword ascii
      $s8 = "BETAsupport@snadboy.com" fullword wide
      $s9 = "support@snadboy.com" fullword wide
      $s14 = "RevelationHelper.dll" fullword ascii
   condition:
      all of them
}