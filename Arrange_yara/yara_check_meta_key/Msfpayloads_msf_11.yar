rule Msfpayloads_msf_11 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-09"
    description = "Metasploit Payloads - file msf.hta"
    family = "None"
    hacker = "None"
    hash1 = "d1daf7bc41580322333a893133d103f7d67f5cd8a3e0f919471061d41cf710b6"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = ".ExpandEnvironmentStrings(\"%PSModulePath%\") + \"..\\powershell.exe\") Then" fullword ascii
    $s2 = "= CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
    $s3 = "= CreateObject(\"Wscript.Shell\") " fullword ascii
  condition:
    all of them
}