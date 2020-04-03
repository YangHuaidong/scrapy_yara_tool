rule telnetd_pl {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file telnetd.pl.txt"
    family = "None"
    hacker = "None"
    hash = "5f61136afd17eb025109304bd8d6d414"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "0ldW0lf" fullword
    $s1 = "However you are lucky :P"
    $s2 = "I'm FuCKeD"
    $s3 = "ioctl($CLIENT{$client}->{shell}, &TIOCSWINSZ, $winsize);#"
    $s4 = "atrix@irc.brasnet.org"
  condition:
    1 of them
}