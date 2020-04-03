rule Suspicious_BAT_Strings {
   meta:
      description = "Detects a string also used in Netwire RAT auxilliary"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      score = 60
      reference = "https://pastebin.com/8qaiyPxs"
      date = "2018-01-05"
   strings:
      $s1 = "ping 192.0.2.2 -n 1" ascii
   condition:
      filesize < 600KB and 1 of them
}