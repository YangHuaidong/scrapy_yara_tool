rule CN_Honker_Pwdump7_Pwdump7 {
    meta:
        description = "Script from disclosed CN Honker Pentest Toolset - file Pwdump7.bat"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "Disclosed CN Honker Pentest Toolset"
        date = "2015-06-23"
		score = 70
        hash = "67d0e215c96370dcdc681bb2638703c2eeea188a"
    strings:
        $s1 = "Pwdump7.exe >pass.txt" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        filesize < 1KB and all of them
}