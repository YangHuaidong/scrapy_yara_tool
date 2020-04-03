rule Molerats_Jul17_Sample_5 {
   meta:
      description = "Detects Molerats sample - July 2017"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
      date = "2017-07-07"
      hash1 = "ebf2423b9de131eab1c61ac395cbcfc2ac3b15bd9c83b96ae0a48619a4a38d0a"
   strings:
      $x1 = "powershell.exe -nop -c \"iex" nocase ascii
      $x2 = ".run('%windir%\\\\SysWOW64\\\\WindowsPowerShell\\\\" ascii
      $a1 = "Net.WebClient).DownloadString" nocase ascii
      $a2 = "gist.githubusercontent.com" nocase ascii
   condition:
      filesize < 200KB and ( 1 of ($x*) or 2 of them )
}