rule Mimikatz_Memory_Rule_1 : APT {
  meta:
    author = "Spider"
    comment = "None"
    date = "12/22/2014"
    description = "Detects password dumper mimikatz in memory (False Positives: an service that could have copied a Mimikatz executable, AV signatures)"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
    type = "memory"
  strings:
    $s1 = "sekurlsa::msv" fullword ascii
    $s2 = "sekurlsa::wdigest" fullword ascii
    $s4 = "sekurlsa::kerberos" fullword ascii
    $s5 = "sekurlsa::tspkg" fullword ascii
    $s6 = "sekurlsa::livessp" fullword ascii
    $s7 = "sekurlsa::ssp" fullword ascii
    $s8 = "sekurlsa::logonPasswords" fullword ascii
    $s9 = "sekurlsa::process" fullword ascii
    $s10 = "ekurlsa::minidump" fullword ascii
    $s11 = "sekurlsa::pth" fullword ascii
    $s12 = "sekurlsa::tickets" fullword ascii
    $s13 = "sekurlsa::ekeys" fullword ascii
    $s14 = "sekurlsa::dpapi" fullword ascii
    $s15 = "sekurlsa::credman" fullword ascii
  condition:
    1 of them
}