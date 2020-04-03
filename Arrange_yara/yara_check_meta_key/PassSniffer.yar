rule PassSniffer {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file PassSniffer.exe"
    family = "None"
    hacker = "None"
    hash = "dcce4c577728e8edf7ed38ac6ef6a1e68afb2c9f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "Sniff" fullword ascii
    $s3 = "GetLas" fullword ascii
    $s4 = "VersionExA" fullword ascii
    $s10 = " Only RuntUZ" fullword ascii
    $s12 = "emcpysetprintf\\" fullword ascii
    $s13 = "WSFtartup" fullword ascii
  condition:
    all of them
}