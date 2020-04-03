import "pe"
rule APT_Thrip_Sample_Jun18_14 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-06-21"
    description = "Detects sample found in Thrip report by Symantec "
    family = "None"
    hacker = "None"
    hash1 = "67dd44a8fbf6de94c4589cf08aa5757b785b26e49e29488e9748189e13d90fb3"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "%SystemRoot%\\System32\\svchost.exe -k " fullword ascii
    $s2 = "spdirs.dll" fullword ascii
    $s3 = "Provides storm installation services such as Publish, and Remove." fullword ascii
    $s4 = "RegSetValueEx(Svchost\\netsvcs)" fullword ascii
    $s5 = "Load %s Error" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and (
    ( pe.exports("InstallA") and pe.exports("InstallB") and pe.exports("InstallC") ) or
    all of them
}