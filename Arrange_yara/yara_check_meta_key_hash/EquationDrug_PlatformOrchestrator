rule EquationDrug_PlatformOrchestrator {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/11"
    description = "EquationDrug - Platform orchestrator - mscfg32.dll, svchost32.dll"
    family = "None"
    hacker = "None"
    hash = "febc4f30786db7804008dc9bc1cebdc26993e240"
    judge = "unknown"
    reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "SERVICES.EXE" fullword wide
    $s1 = "\\command.com" fullword wide
    $s2 = "Microsoft(R) Windows (TM) Operating System" fullword wide
    $s3 = "LSASS.EXE" fullword wide
    $s4 = "Windows Configuration Services" fullword wide
    $s8 = "unilay.dll" fullword ascii
  condition:
    all of them
}