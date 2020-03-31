rule Netview_Hacktool_Output {
   meta:
      description = "Network domain enumeration tool output - often used by attackers - file filename.txt"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/mubix/netview"
      date = "2016-03-07"
      score = 60
   strings:
      $s1 = "[*] Using interval:" fullword
      $s2 = "[*] Using jitter:" fullword
      $s3 = "[+] Number of hosts:" fullword
   condition:
      2 of them
}