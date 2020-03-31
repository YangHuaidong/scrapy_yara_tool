rule Fscan_Portscanner {
  meta:
    author = Spider
    comment = None
    date = 2017-01-06
    description = Fscan port scanner scan output / strings
    family = None
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://twitter.com/JamesHabben/status/817112447970480128
    threatname = Fscan[Portscanner
    threattype = Portscanner.yar
  strings:
    $s1 = "Time taken:" fullword ascii
    $s2 = "Scan finished at" fullword ascii
    $s3 = "Scan started at" fullword ascii
  condition:
    filesize < 20KB and 3 of them
}