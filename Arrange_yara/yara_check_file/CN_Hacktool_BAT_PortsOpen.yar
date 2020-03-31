rule CN_Hacktool_BAT_PortsOpen {
  meta:
    author = Spider
    comment = None
    date = 12.10.2014
    description = Detects a chinese BAT hacktool for local port evaluation
    family = PortsOpen
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 60
    threatname = CN[Hacktool]/BAT.PortsOpen
    threattype = Hacktool
  strings:
    $s0 = "for /f \"skip=4 tokens=2,5\" %%a in ('netstat -ano -p TCP') do (" ascii
    $s1 = "in ('tasklist /fi \"PID eq %%b\" /FO CSV') do " ascii
    $s2 = "@echo off" ascii
  condition:
    all of them
}