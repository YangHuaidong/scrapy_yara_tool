rule Hacktool_Strings_p0wnedShell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-14"
    description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedShell.cs"
    family = "None"
    hacker = "None"
    hash1 = "e1f35310192416cd79e60dba0521fc6eb107f3e65741c344832c46e9b4085e60"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/Cn33liz/p0wnedShell"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Invoke-TokenManipulation" fullword ascii
    $x2 = "windows/meterpreter" fullword ascii
    $x3 = "lsadump::dcsync" fullword ascii
    $x4 = "p0wnedShellx86" fullword ascii
    $x5 = "p0wnedShellx64" fullword ascii
    $x6 = "Invoke_PsExec()" fullword ascii
    $x7 = "Invoke-Mimikatz" fullword ascii
    $x8 = "Invoke_Shellcode()" fullword ascii
    $x9 = "Invoke-ReflectivePEInjection" ascii
  condition:
    1 of them
}