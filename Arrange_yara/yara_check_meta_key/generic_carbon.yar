rule generic_carbon {
  meta:
    author = "Spider"
    comment = "None"
    contact = "github@eset.com"
    date = "2017-03-30"
    description = "Turla Carbon malware"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "BSD 2-Clause"
    reference = "https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/"
    source = "https://github.com/eset/malware-ioc/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "ModStart"
    $t1 = "STOP|OK"
    $t2 = "STOP|KILL"
  condition:
    (uint16(0) == 0x5a4d) and (1 of ($s*)) and (1 of ($t*))
}