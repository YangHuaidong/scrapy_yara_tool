rule CN_Honker_Alien_command {
    meta:
        description = "Script from disclosed CN Honker Pentest Toolset - file command.txt"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "Disclosed CN Honker Pentest Toolset"
        date = "2015-06-23"
		score = 70
        hash = "5896b74158ef153d426fba76c2324cd9c261c709"
    strings:
        $s0 = "for /d %i in (E:\\freehost\\*) do @echo %i" fullword ascii /* PEStudio Blacklist: strings */
        $s1 = "/c \"C:\\windows\\temp\\cscript\" C:\\windows\\temp\\iis.vbs" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        filesize < 8KB and all of them
}