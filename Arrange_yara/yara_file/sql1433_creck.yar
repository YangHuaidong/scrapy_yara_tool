rule sql1433_creck {
    meta:
        description = "Chinese Hacktool Set - file creck.bat"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "189c11a3b268789a3fbcfac3bd4e03cbfde87b1d"
    strings:
        $s0 = "start anhao3.exe -i S.txt -p  pass3.txt -o anhao.txt -l Them.txt -t 1000" fullword ascii 
        $s1 = "start anhao1.exe -i S.txt -p  pass1.txt -o anhao.txt -l Them.txt -t 1000" fullword ascii 
        $s2 = "start anhao2.exe -i S.txt -p  pass2.txt -o anhao.txt -l Them.txt -t 1000" fullword ascii 
    condition:
        uint16(0) == 0x7473 and filesize < 1KB and 1 of them
}