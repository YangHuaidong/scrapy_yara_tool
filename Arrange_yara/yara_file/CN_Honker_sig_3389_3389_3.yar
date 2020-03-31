rule CN_Honker_sig_3389_3389_3 {
    meta:
        description = "Script from disclosed CN Honker Pentest Toolset - file 3389.bat"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "Disclosed CN Honker Pentest Toolset"
        date = "2015-06-23"
		score = 70
        hash = "cfedec7bd327897694f83501d76063fe16b13450"
    strings:
        $s1 = "echo \"fDenyTSConnections\"=dword:00000000>>3389.reg " fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "echo \"PortNumber\"=dword:00000d3d>>3389.reg " fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "echo [HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server]>>" ascii /* PEStudio Blacklist: strings */
    condition:
        filesize < 2KB and all of them
}