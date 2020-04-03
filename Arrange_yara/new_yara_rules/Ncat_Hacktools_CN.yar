rule Ncat_Hacktools_CN {
  meta:
    author = "Spider"
    comment = "None"
    date = "17.11.14"
    description = "Disclosed hacktool set - file nc.exe"
    family = "None"
    hacker = "None"
    hash = "001c0c01c96fa56216159f83f6f298755366e528"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "nc -l -p port [options] [hostname] [port]" fullword ascii
    $s2 = "nc [-options] hostname port[s] [ports] ... " fullword ascii
    $s3 = "gethostpoop fuxored" fullword ascii
    $s6 = "VERNOTSUPPORTED" fullword ascii
    $s7 = "%s [%s] %d (%s)" fullword ascii
    $s12 = " `--%s' doesn't allow an argument" fullword ascii
  condition:
    all of them
}