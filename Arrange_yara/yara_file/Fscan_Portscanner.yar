rule Fscan_Portscanner {
   meta:
      description = "Fscan port scanner scan output / strings"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/JamesHabben/status/817112447970480128"
      date = "2017-01-06"
   strings:
      $s1 = "Time taken:" fullword ascii
      $s2 = "Scan finished at" fullword ascii
      $s3 = "Scan started at" fullword ascii
   condition:
      filesize < 20KB and 3 of them
}