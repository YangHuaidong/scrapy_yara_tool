rule PoisonIvy_Sample_6 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-03"
    description = "Detects PoisonIvy RAT sample set"
    family = "None"
    hacker = "None"
    hash1 = "8c2630ab9b56c00fd748a631098fa4339f46d42b"
    hash2 = "36b4cbc834b2f93a8856ff0e03b7a6897fb59bd3"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "VT Analysis"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "124.133.252.150" fullword ascii /* score: '9.5' */
    $x3 = "http://124.133.254.171/up/up.asp?id=%08x&pcname=%s" fullword ascii /* score: '24.01' */
    $z1 = "\\temp\\si.txt" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.01' */
    $z2 = "Daemon Dynamic Link Library" fullword wide /* PEStudio Blacklist: strings */ /* score: '11.02' */
    $z3 = "Microsoft Windows CTF Loader" fullword wide /* PEStudio Blacklist: strings */ /* score: '11.03' */
    $z4 = "\\tappmgmts.dll" fullword ascii /* score: '11.005' */
    $z5 = "\\appmgmts.dll" fullword ascii /* score: '11.0' */
    $s0 = "%USERPROFILE%\\AppData\\Local\\Temp\\Low\\ctfmon.log" fullword ascii /* PEStudio Blacklist: strings */ /* score: '43.015' */
    $s1 = "%USERPROFILE%\\AppData\\Local\\Temp\\ctfmon.tmp" fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.015' */
    $s2 = "\\temp\\ctfmon.tmp" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.01' */
    $s3 = "SOFTWARE\\Classes\\http\\shell\\open\\commandV" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.025' */
    $s4 = "CONNECT %s:%i HTTP/1.0" fullword ascii /* PEStudio Blacklist: strings */ /* score: '19.02' */
    $s5 = "start read histry key" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.04' */
    $s6 = "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"" fullword ascii /* score: '18.03' */
    $s7 = "[password]%s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.025' */
    $s8 = "Daemon.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.02' */
    $s9 = "[username]%s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '12.035' */
    $s10 = "advpack" fullword ascii /* score: '7.005' */
    $s11 = "%s%2.2X" fullword ascii /* score: '7.0' */
    $s12 = "advAPI32" fullword ascii /* score: '6.015' */
  condition:
    ( uint16(0) == 0x5a4d and 1 of ($x*) ) or
    ( 8 of ($s*) ) or
    ( 1 of ($z*) and 3 of ($s*) )
}