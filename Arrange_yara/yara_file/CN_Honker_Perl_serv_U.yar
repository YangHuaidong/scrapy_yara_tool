rule CN_Honker_Perl_serv_U {
    meta:
        description = "Script from disclosed CN Honker Pentest Toolset - file Perl-serv-U.pl"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "Disclosed CN Honker Pentest Toolset"
        date = "2015-06-23"
		score = 70
        hash = "f333c597ff746ebd5a641fbc248497d61e3ec17b"
    strings:
        $s1 = "$dir = 'C:\\\\WINNT\\\\System32\\\\';" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "$sock = IO::Socket::INET->new(\"127.0.0.1:$adminport\") || die \"fail\";" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        filesize < 8KB and all of them
}