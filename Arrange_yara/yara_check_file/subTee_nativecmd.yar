rule subTee_nativecmd {
  meta:
    author = Spider
    comment = None
    date = 2015-07-10
    description = NativeCmd - used by various threat groups
    family = None
    hacker = None
    hash = 758e6b519f6c0931ff93542b767524fc1eab589feb5cfc3854c77842f9785c92
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/
    score = 40
    threatname = subTee[nativecmd
    threattype = nativecmd.yar
  strings:
    $x1 = "RunFile: couldn't load SHELL32.DLL!" ascii wide /* PEStudio Blacklist: strings */ /* score: '27.00' */
    $x2 = "RunFile: couldn't find ShellExecuteExA/W in SHELL32.DLL!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '35.00' */
    $x3 = "Error executing CreateProcess()!!" fullword wide /* PEStudio Blacklist: strings */ /* score: '31.00' */
    $x4 = "cmdcmdline" fullword wide /* score: '11.00' */
    $x5 = "Invalid input handle!!!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00' */
    $s1 = "Process %d terminated" fullword wide /* PEStudio Blacklist: strings */ /* score: '24.00' */
    $s2 = "Process is not running any more" fullword wide /* PEStudio Blacklist: strings */ /* score: '22.00' */
    $s3 = "javacpl.exe" fullword wide /* score: '3.00' */ /* Goodware String - occured 2 times */
    $s4 = "Windows NT Version %lu.%lu" fullword wide /* PEStudio Blacklist: os */ /* score: '19.00' */
    $s5 = "Usage: destination [reference]" fullword wide /* PEStudio Blacklist: strings */ /* score: '16.00' */
    $s6 = ".com;.exe;.bat;.cmd" fullword wide /* score: '15.00' */
    $s7 = ") -%s-> %s (" fullword ascii /* score: '14.00' */
    $s8 = "cmdextversion" fullword wide /* score: '14.00' */
    $s10 = "\"%s\" /K %s" fullword wide /* score: '11.02' */
    $s12 = "DEBUG: Cannot allocate memory for ptrNextNode->ptrNext!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00' */
    $s13 = "Failed to build full directory path" fullword wide /* score: '10.00' */
    $s14 = "DEBUG: Cannot allocate memory for ptrFileArray!" fullword ascii /* PEStudio Blacklist: strings */ /* score: '9.00' */
    $s15 = "%-8s %-3s  %*s %s  %s" fullword wide /* score: '8.00' */
    $s16 = " %%%c in (%s) do " fullword wide /* score: '8.00' */
  condition:
    uint16(0) == 0x5a4d and ( 2 of ($x*) or 6 of ($s*) )
}