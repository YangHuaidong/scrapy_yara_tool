rule StoneDrill_Service_Install {
   meta:
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      description = "Rule to detect Batch file from StoneDrill report"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
   strings:
      $s1 = "127.0.0.1 >nul && sc config" ascii
      $s2 = "LocalService\" && ping -n" ascii fullword
      $s3 = "127.0.0.1 >nul && sc start" ascii fullword
      $s4 = "sc config NtsSrv binpath= \"C:\\WINDOWS\\system32\ntssrvr64.exe" ascii
   condition:
      2 of them and filesize < 500
}