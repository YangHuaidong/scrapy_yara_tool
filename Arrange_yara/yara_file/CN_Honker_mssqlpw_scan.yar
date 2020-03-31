rule CN_Honker_mssqlpw_scan {
    meta:
        description = "Script from disclosed CN Honker Pentest Toolset - file mssqlpw scan.txt"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "Disclosed CN Honker Pentest Toolset"
        date = "2015-06-23"
		score = 70
        hash = "e49def9d72bfef09a639ef3f7329083a0b8b151c"
    strings:
        $s0 = "response.Write(\"I Get it ! Password is <font color=red>\" & str & \"</font><BR>" ascii /* PEStudio Blacklist: strings */
        $s1 = "response.Write \"Done!<br>Process \" & tTime & \" s\"" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        filesize < 6KB and all of them
}