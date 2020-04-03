rule Empire_Agent_Gen {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-11-05"
    description = "Detects Empire component - from files agent.ps1, agent.ps1"
    family = "None"
    hacker = "None"
    hash1 = "380fd09bfbe47d5c8c870c1c97ff6f44982b699b55b61e7c803d3423eb4768db"
    hash2 = "380fd09bfbe47d5c8c870c1c97ff6f44982b699b55b61e7c803d3423eb4768db"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/adaptivethreat/Empire"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$wc.Headers.Add(\"User-Agent\",$script:UserAgent)" fullword ascii
    $s2 = "$min = [int]((1-$script:AgentJitter)*$script:AgentDelay)" fullword ascii
    $s3 = "if ($script:AgentDelay -ne 0){" fullword ascii
  condition:
    ( uint16(0) == 0x660a and filesize < 100KB and 1 of them ) or all of them
}