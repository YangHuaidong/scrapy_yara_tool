rule GetUserSPNs_PS1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-05-21"
    description = "Auto-generated rule - file GetUserSPNs.ps1"
    family = "None"
    hacker = "None"
    hash1 = "1b69206b8d93ac86fe364178011723f4b1544fff7eb1ea544ab8912c436ddc04"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/skelsec/PyKerberoast"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$ForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()" fullword ascii
    $s2 = "@{Name=\"PasswordLastSet\";      Expression={[datetime]::fromFileTime($result.Properties[\"pwdlastset\"][0])} } #, `" fullword ascii
    $s3 = "Write-Host \"No Global Catalogs Found!\"" fullword ascii
    $s4 = "$searcher.PropertiesToLoad.Add(\"pwdlastset\") | Out-Null" fullword ascii
  condition:
    2 of them
}