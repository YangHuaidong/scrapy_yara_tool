rule CN_Honker_Tuoku_script_MSSQL_ {
    meta:
        description = "Script from disclosed CN Honker Pentest Toolset - file MSSQL_.asp"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "Disclosed CN Honker Pentest Toolset"
        date = "2015-06-23"
		score = 70
        hash = "7097c21f92306983add3b5b29a517204cd6cd819"
    strings:
        $s1 = "GetLoginCookie = Request.Cookies(Cookie_Login)" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "if ShellPath=\"\" Then ShellPath = \"c:\\\\windows\\\\system32\\\\cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
        $s8 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        filesize < 100KB and all of them
}