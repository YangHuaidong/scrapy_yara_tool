rule Mimikatz_Logfile
{
   meta:
      description = "Detects a log file generated by malicious hack tool mimikatz"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      score = 80
      date = "2015/03/31"
   strings:
      $s1 = "SID               :" ascii fullword
      $s2 = "* NTLM     :" ascii fullword
      $s3 = "Authentication Id :" ascii fullword
      $s4 = "wdigest :" ascii fullword
   condition:
      all of them
}