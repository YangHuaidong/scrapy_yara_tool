rule ps1_toolkit_Persistence {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-09-04"
    description = "Auto-generated rule - file Persistence.ps1"
    family = "None"
    hacker = "None"
    hash1 = "e1a4dd18b481471fc25adea6a91982b7ffed1c2d393c8c17e6e542c030ac6cbd"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/vysec/ps1-toolkit"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\"`\"```$Filter=Set-WmiInstance -Class __EventFilter -Namespace ```\"root\\subscription```" ascii
    $s2 = "}=$PROFILE.AllUsersAllHosts;${" ascii
    $s3 = "C:\\PS> $ElevatedOptions = New-ElevatedPersistenceOption -Registry -AtStartup"  ascii
    $s4 = "= gwmi Win32_OperatingSystem | select -ExpandProperty OSArchitecture"  ascii
    $s5 = "-eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAxADQAQwA='))))"  ascii
    $s6 = "}=$PROFILE.CurrentUserAllHosts;${"  ascii
    $s7 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBPAG4ASQBkAGwAZQA=')" ascii
    $s8 = "[System.Text.AsciiEncoding]::ASCII.GetString($MZHeader)" fullword ascii
  condition:
    ( uint16(0) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}