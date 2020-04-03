rule CN_Honker_syconfig {
    meta:
        description = "Script from disclosed CN Honker Pentest Toolset - file syconfig.dll"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "Disclosed CN Honker Pentest Toolset"
        date = "2015-06-23"
		score = 70
        hash = "ff75353df77d610d3bccfbffb2c9dfa258b2fac9"
    strings:
        $s9 = "Hashq.CrackHost+FormUnit" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        uint16(0) == 0x0100 and filesize < 18KB and all of them
}