rule FPipe2_0 {
  meta:
    author = Spider
    comment = None
    date = 23.11.14
    description = Disclosed hacktool set (old stuff) - file FPipe2.0.exe
    family = None
    hacker = None
    hash = 891609db7a6787575641154e7aab7757e74d837b
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 60
    threatname = FPipe2[0
    threattype = 0.yar
  strings:
    $s0 = "made to port 80 of the remote machine at 192.168.1.101 with the" fullword ascii
    $s1 = "Unable to resolve hostname \"%s\"" fullword ascii
    $s2 = " -s    - outbound connection source port number" fullword ascii
    $s3 = "source port for that outbound connection being set to 53 also." fullword ascii
    $s4 = "http://www.foundstone.com" fullword ascii
    $s19 = "FPipe" fullword ascii
  condition:
    all of them
}