rule CN_Honker_Webshell_ASPX_sniff {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file sniff.txt"
    family = "None"
    hacker = "None"
    hash = "e246256696be90189e6d50a4ebc880e6d9e28dfd"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "if (!logIt && my_s_smtp && (dport == 25 || sport == 25))" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 91KB and all of them
}