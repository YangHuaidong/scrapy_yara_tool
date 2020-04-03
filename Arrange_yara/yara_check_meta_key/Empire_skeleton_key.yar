rule Empire_skeleton_key {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-08-06"
    description = "Empire - a pure PowerShell post-exploitation agent - file skeleton_key.py"
    family = "None"
    hacker = "None"
    hash = "3d02f16dcc38faaf5e97e4c5dbddf761f2816004775e6af8826cde9e29bb750f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/PowerShellEmpire/Empire"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "script += \"Invoke-Mimikatz -Command '\\\"\" + command + \"\\\"';\"" fullword ascii
    $s2 = "script += '\"Skeleton key implanted. Use password \\'mimikatz\\' for access.\"'" fullword ascii
    $s3 = "command = \"misc::skeleton\"" fullword ascii
    $s4 = "\"ONLY APPLICABLE ON DOMAIN CONTROLLERS!\")," fullword ascii
  condition:
    filesize < 6KB and 2 of them
}