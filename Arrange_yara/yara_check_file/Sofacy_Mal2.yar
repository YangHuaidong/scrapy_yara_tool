rule Sofacy_Mal2 {
    meta:
        description = "Sofacy Group Malware Sample 2"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
        date = "2015-06-19"
        hash = "566ab945f61be016bfd9e83cc1b64f783b9b8deb891e6d504d3442bc8281b092"
        score = 70
    strings:
        $x1 = "PROJECT\\XAPS_OBJECTIVE_DLL\\" ascii
        $x2 = "XAPS_OBJECTIVE.dll" fullword ascii
        $s1 = "i`m wait" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ( 1 of ($x*) ) and $s1
}