rule CN_Tools_srss {
    meta:
        description = "Chinese Hacktool Set - file srss.bat"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "092ab0797947692a247fe80b100fb4df0f9c37a0"
    strings:
        $s0 = "srss.exe -idx 0 -ip"
        $s1 = "-port 21 -logfilter \"_USER ,_P" ascii 
    condition:
        filesize < 100 and all of them
}