rule WildNeutron_Sample_7 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-07-10"
    description = "Wild Neutron APT Sample Rule - file a14d31eb965ea8a37ebcc3b5635099f2ca08365646437c770212d534d504ff3c"
    family = "None"
    hacker = "None"
    hash = "a14d31eb965ea8a37ebcc3b5635099f2ca08365646437c770212d534d504ff3c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "checking match for '%s' user %s host %s addr %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '24.00' */
    $s1 = "PEM_read_bio_PrivateKey failed" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00' */
    $s2 = "usage: %s [-ehR] [-f log_facility] [-l log_level] [-u umask]" fullword ascii /* score: '23.00' */
    $s3 = "%s %s for %s%.100s from %.200s port %d%s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00' */
    $s4 = "clapi32.dll" fullword ascii /* score: '21.00' */
    $s5 = "Connection from %s port %d" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00' */
    $s6 = "/usr/etc/ssh_known_hosts" fullword ascii /* PEStudio Blacklist: strings */ /* score: '16.00' */
    $s7 = "Version: %s - %s %s %s %s" fullword ascii /* score: '16.00' */
    $s8 = "[-] connect()" fullword ascii /* PEStudio Blacklist: strings */ /* score: '13.00' */
    $s9 = "/bin/sh /usr/etc/sshrc" fullword ascii /* score: '12.42' */
    $s10 = "kexecdhs.c" fullword ascii /* score: '12.00' */
    $s11 = "%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s" fullword ascii /* score: '11.00' */
  condition:
    uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}