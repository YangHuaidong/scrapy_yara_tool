rule PScan_Portscan_1 {
   meta:
      description = "PScan - Port Scanner"
      author = "F. Roth"
      score = 50
   strings:
      $a = "00050;0F0M0X0a0v0}0"
      $b = "vwgvwgvP76"
      $c = "Pr0PhOFyP"
   condition:
      all of them
}