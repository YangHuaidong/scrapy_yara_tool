rule WildNeutron_javacpl {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-07-10"
    description = "Wild Neutron APT Sample Rule"
    family = "None"
    hacker = "None"
    hash1 = "683f5b476f8ffe87ec22b8bab57f74da4a13ecc3a5c2cbf951999953c2064fc9"
    hash2 = "758e6b519f6c0931ff93542b767524fc1eab589feb5cfc3854c77842f9785c92"
    hash3 = "8ca7ed720babb32a6f381769ea00e16082a563704f8b672cb21cf11843f4da7a"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
    score = 60
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "javacpl.exe" fullword wide /* score: '3.00' */ /* Goodware String - occured 2 times */
    $s0 = "RunFile: couldn't find ShellExecuteExA/W in SHELL32.DLL!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '35.00' */
    $s1 = "Error executing CreateProcess()!!" fullword wide /* PEStudio Blacklist: strings */ /* score: '31.00' */
    $s2 = "http://www.java.com/en/download/installed.jsp?detect=jre" fullword ascii /* PEStudio Blacklist: strings */ /* score: '28.00' */
    $s3 = "RunFile: couldn't load SHELL32.DLL!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00' */
    $s4 = "Process is not running any more" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00' */
    $s6 = "Windows NT Version %lu.%lu" fullword wide /* PEStudio Blacklist: os */ /* score: '19.00' */
    $s7 = "Usage: destination [reference]" fullword wide /* PEStudio Blacklist: strings */ /* score: '16.00' */
    $s8 = "Invalid input handle!!!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '15.00' */
    $s9 = ".com;.exe;.bat;.cmd" fullword wide /* score: '15.00' */
    $s10 = ") -%s-> %s (" fullword ascii /* score: '14.00' */
    $s11 = "cmdextversion" fullword wide /* score: '14.00' */
    $s12 = "Invalid pid (%s)" fullword wide /* PEStudio Blacklist: strings */ /* score: '13.00' */
    $s13 = "\"%s\" /K %s" fullword wide /* score: '11.02' */
    $s14 = "Error setting %s (%s)" fullword wide /* score: '11.00' */
    $s16 = "cmdcmdline" fullword wide /* score: '11.00' */
    $s39 = "2008R2" fullword ascii /* PEStudio Blacklist: os */ /* score: '8.00' */
  condition:
    uint16(0) == 0x5a4d and filesize < 1677KB and all of them
}