rule Empire_Persistence {
  meta:
    author = Spider
    comment = None
    date = 2015-08-06
    description = Empire - a pure PowerShell post-exploitation agent - file Persistence.psm1
    family = None
    hacker = None
    hash = ae8875f7fcb8b4de5cf9721a9f5a9f7782f7c436c86422060ecdc5181e31092f
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://github.com/PowerShellEmpire/Empire
    score = 70
    threatname = Empire[Persistence
    threattype = Persistence.yar
  strings:
    $s1 = "C:\\PS>Add-Persistence -ScriptBlock $RickRoll -ElevatedPersistenceOption $ElevatedOptions -UserPersistenceOption $UserOptions -V" ascii
    $s2 = "# Execute the following to remove the user-level persistent payload" fullword ascii
    $s3 = "$PersistantScript = $PersistantScript.ToString().Replace('EXECUTEFUNCTION', \"$PersistenceScriptName -Persist\")" fullword ascii
  condition:
    filesize < 108KB and 1 of them
}