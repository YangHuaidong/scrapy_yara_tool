rule EQGRP_workit {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - file workit.py"
    family = "None"
    hacker = "None"
    hash1 = "fb533b4d255b4e6072a4fa2e1794e38a165f9aa66033340c2f4f8fd1da155fac"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "macdef init > /tmp/.netrc;" fullword ascii
    $s2 = "/usr/bin/wget http://" fullword ascii
    $s3 = "HOME=/tmp ftp" fullword ascii
    $s4 = " >> /tmp/.netrc;" fullword ascii
    $s5 = "/usr/rapidstream/bin/tftp" fullword ascii
    $s6 = "created shell_command:" fullword ascii
    $s7 = "rm -f /tmp/.netrc;" fullword ascii
    $s8 = "echo quit >> /tmp/.netrc;" fullword ascii
    $s9 = "echo binary >> /tmp/.netrc;" fullword ascii
    $s10 = "chmod 600 /tmp/.netrc;" fullword ascii
    $s11 = "created cli_command:" fullword ascii
  condition:
    6 of them
}