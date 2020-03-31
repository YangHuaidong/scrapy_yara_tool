rule CN_Honker_Injection_Transit_jmCook {
    meta:
        description = "Script from disclosed CN Honker Pentest Toolset - file jmCook.asp"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "Disclosed CN Honker Pentest Toolset"
        date = "2015-06-23"
		score = 70
        hash = "5e1851c77ce922e682333a3cb83b8506e1d7395d"
    strings:
        $s1 = ".Open \"POST\",PostUrl,False" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "JmdcwName=request(\"jmdcw\")" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        filesize < 9KB and all of them
}