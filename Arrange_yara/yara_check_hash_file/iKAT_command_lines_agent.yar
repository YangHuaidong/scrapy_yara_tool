rule iKAT_command_lines_agent {
  meta:
    author = Spider
    comment = None
    date = 05.11.14
    description = iKAT hack tools set agent - file ikat.exe
    family = agent
    hacker = None
    hash = c802ee1e49c0eae2a3fc22d2e82589d857f96d94
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://ikat.ha.cked.net/Windows/functions/ikatfiles.html
    score = 75
    threatname = iKAT[command]/lines.agent
    threattype = command
  strings:
    $s0 = "Extended Module: super mario brothers" fullword ascii
    $s1 = "Extended Module: " fullword ascii
    $s3 = "ofpurenostalgicfeeling" fullword ascii
    $s8 = "-supermariobrotheretic" fullword ascii
    $s9 = "!http://132.147.96.202:80" fullword ascii
    $s12 = "iKAT Exe Template" fullword ascii
    $s15 = "withadancyflavour.." fullword ascii
    $s16 = "FastTracker v2.00   " fullword ascii
  condition:
    4 of them
}