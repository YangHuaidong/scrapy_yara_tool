rule Leviathan_CobaltStrike_Sample_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-10-18"
    description = "Detects Cobalt Strike sample from Leviathan report"
    family = "None"
    hacker = "None"
    hash1 = "5860ddc428ffa900258207e9c385f843a3472f2fbf252d2f6357d458646cf362"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/MZ7dRg"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "a54c81.dll" fullword ascii
    $x2 = "%d is an x64 process (can't inject x86 content)" fullword ascii
    $x3 = "Failed to impersonate logged on user %d (%u)" fullword ascii
    $s1 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
    $s2 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword ascii
    $s3 = "could not run command (w/ token) because of its length of %d bytes!" fullword ascii
    $s4 = "could not write to process memory: %d" fullword ascii
    $s5 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" fullword ascii
    $s6 = "Could not connect to pipe (%s): %d" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 600KB and ( 1 of ($x*) or 3 of them )
}