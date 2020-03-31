rule dll_UnReg {
    meta:
        description = "Chinese Hacktool Set - file UnReg.bat"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "d5e24ba86781c332d0c99dea62f42b14e893d17e"
    strings:
        $s0 = "regsvr32.exe /u C:\\windows\\system32\\PacketX.dll" fullword ascii 
        $s1 = "del /F /Q C:\\windows\\system32\\PacketX.dll" fullword ascii 
    condition:
        filesize < 1KB and 1 of them
}