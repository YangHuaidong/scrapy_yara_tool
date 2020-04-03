rule CN_Honker_mafix_root {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Script from disclosed CN Honker Pentest Toolset - file root"
    family = "None"
    hacker = "None"
    hash = "826778ef9c22177d41698b467586604e001fed19"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "echo \"# vbox (voice box) getty\" >> /tmp/.init1" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "cp /var/log/tcp.log $HOMEDIR/.owned/bex2/snifflog" fullword ascii
    $s2 = "if [ -f /sbin/xlogin ]; then" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 96KB and all of them
}