rule CN_Hacktool_BAT_PortsOpen {
   meta:
      description = "Detects a chinese BAT hacktool for local port evaluation"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      score = 60
      date = "12.10.2014"
   strings:
      $s0 = "for /f \"skip=4 tokens=2,5\" %%a in ('netstat -ano -p TCP') do (" ascii
      $s1 = "in ('tasklist /fi \"PID eq %%b\" /FO CSV') do " ascii
      $s2 = "@echo off" ascii
   condition:
      all of them
}