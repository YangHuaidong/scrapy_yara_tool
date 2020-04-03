rule sig_238_fscan {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file fscan.exe"
    family = "None"
    hacker = "None"
    hash = "d5646e86b5257f9c83ea23eca3d86de336224e55"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "FScan v1.12 - Command line port scanner." fullword ascii
    $s2 = " -n    - no port scanning - only pinging (unless you use -q)" fullword ascii
    $s5 = "Example: fscan -bp 80,100-200,443 10.0.0.1-10.0.1.200" fullword ascii
    $s6 = " -z    - maximum simultaneous threads to use for scanning" fullword ascii
    $s12 = "Failed to open the IP list file \"%s\"" fullword ascii
    $s13 = "http://www.foundstone.com" fullword ascii
    $s16 = " -p    - TCP port(s) to scan (a comma separated list of ports/ranges) " fullword ascii
    $s18 = "Bind port number out of range. Using system default." fullword ascii
    $s19 = "fscan.exe" fullword wide
  condition:
    4 of them
}