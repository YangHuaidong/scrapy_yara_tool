rule Winexe_RemoteExecution {
    meta:
        description = "Winexe tool used by Sofacy group several APT cases"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
        date = "2015-06-19"
        hash = "5130f600cd9a9cdc82d4bad938b20cbd2f699aadb76e7f3f1a93602330d9997d"
        score = 70
    strings:
        $s1 = "\\\\.\\pipe\\ahexec" fullword ascii
        $s2 = "implevel" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 115KB and all of them
}