rule ps1_toolkit_PowerUp_2 {
  meta:
    author = Spider
    comment = None
    date = 2016-09-04
    description = Auto-generated rule - from files PowerUp.ps1
    family = 2
    hacker = None
    hash1 = fc65ec85dbcd49001e6037de9134086dd5559ac41ac4d1adf7cab319546758ad
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://github.com/vysec/ps1-toolkit
    score = 80
    threatname = ps1[toolkit]/PowerUp.2
    threattype = toolkit
  strings:
    $s1 = "if($MyConString -like $([Text.Encoding]::Unicode.GetString([Convert]::" ascii
    $s2 = "FromBase64String('KgBwAGEAcwBzAHcAbwByAGQAKgA=')))) {" ascii
    $s3 = "$Null = Invoke-ServiceStart" ascii
    $s4 = "Write-Warning \"[!] Access to service $" ascii
    $s5 = "} = $MyConString.Split(\"=\")[1].Split(\";\")[0]" ascii
    $s6 = "} += \"net localgroup ${" ascii
  condition:
    ( uint16(0) == 0xbbef and filesize < 2000KB and 2 of them ) or ( 4 of them )
}