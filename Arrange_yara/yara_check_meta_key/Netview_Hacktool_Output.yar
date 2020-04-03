rule Netview_Hacktool_Output {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-03-07"
    description = "Network domain enumeration tool output - often used by attackers - file filename.txt"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/mubix/netview"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "[*] Using interval:" fullword
    $s2 = "[*] Using jitter:" fullword
    $s3 = "[+] Number of hosts:" fullword
  condition:
    2 of them
}