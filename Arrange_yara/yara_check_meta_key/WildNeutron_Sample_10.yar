rule WildNeutron_Sample_10 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-07-10"
    description = "Wild Neutron APT Sample Rule - file 1d3bdabb350ba5a821849893dabe5d6056bf7ba1ed6042d93174ceeaa5d6dad7"
    family = "None"
    hacker = "None"
    hash = "1d3bdabb350ba5a821849893dabe5d6056bf7ba1ed6042d93174ceeaa5d6dad7"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $n1 = "/c for /L %%i in (1,1,2) DO ping 127.0.0.1 -n 3 & type %%windir%%\\notepad.exe > %s & del /f %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '46.00' */
    $s1 = "%SYSTEMROOT%\\temp\\_dbg.tmp" fullword ascii /* PEStudio Blacklist: strings */ /* score: '37.00' */
    $s2 = "%SYSTEMROOT%\\SysWOW64\\mspool.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.17' */
    $s3 = "%SYSTEMROOT%\\System32\\dpcore16t.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.17' */
    $s4 = "%SYSTEMROOT%\\System32\\wdigestEx.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.17' */
    $s5 = "%SYSTEMROOT%\\System32\\mspool.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.17' */
    $s6 = "%SYSTEMROOT%\\System32\\kernel32.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00' */
    $s7 = "%SYSTEMROOT%\\SysWOW64\\iastor32.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.17' */
    $s8 = "%SYSTEMROOT%\\System32\\msvcse.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.17' */
    $s9 = "%SYSTEMROOT%\\System32\\mshtaex.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.17' */
    $s10 = "%SYSTEMROOT%\\System32\\iastor32.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.17' */
    $s11 = "%SYSTEMROOT%\\SysWOW64\\mshtaex.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.17' */
    $x1 = "wdigestEx.dll" fullword ascii /* PEStudio Blacklist: strings */ /* score: '26.00' */
    $x2 = "dpcore16t.dll" fullword ascii /* score: '21.00' */
    $x3 = "mspool.dll" fullword ascii /* score: '21.00' */
    $x4 = "msvcse.exe" fullword ascii /* score: '20.00' */
    $x5 = "mshtaex.exe" fullword wide /* score: '20.00' */
    $x6 = "iastor32.exe" fullword ascii /* score: '20.00' */
    $y1 = "Installer.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '25.00' */
    $y2 = "Info: Process %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '21.00' */
    $y3 = "Error: GetFileTime %s 0x%x" fullword ascii /* score: '17.00' */
    $y4 = "Install succeeded" fullword ascii /* PEStudio Blacklist: strings */ /* score: '10.00' */
    $y5 = "Error: RegSetValueExA 0x%x" fullword ascii /* score: '9.00' */
  condition:
    uint16(0) == 0x5a4d and filesize < 400KB and
    $n1 or ( 1 of ($s*) and 1 of ($x*) and 3 of ($y*) )
}