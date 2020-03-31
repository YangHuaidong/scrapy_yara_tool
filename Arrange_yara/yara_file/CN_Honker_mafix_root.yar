rule CN_Honker_mafix_root {
    meta:
        description = "Script from disclosed CN Honker Pentest Toolset - file root"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "Disclosed CN Honker Pentest Toolset"
        date = "2015-06-23"
		score = 70
        hash = "826778ef9c22177d41698b467586604e001fed19"
    strings:
        $s0 = "echo \"# vbox (voice box) getty\" >> /tmp/.init1" fullword ascii /* PEStudio Blacklist: strings */
        $s1 = "cp /var/log/tcp.log $HOMEDIR/.owned/bex2/snifflog" fullword ascii
        $s2 = "if [ -f /sbin/xlogin ]; then" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        filesize < 96KB and all of them
}