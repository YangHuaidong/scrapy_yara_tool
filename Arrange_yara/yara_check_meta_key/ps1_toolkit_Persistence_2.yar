rule ps1_toolkit_Persistence_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-09-04"
    description = "Auto-generated rule - from files Persistence.ps1"
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
    $s1 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBPAG4ASQBkAGwAZQA=')" ascii
    $s2 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBEAGEAaQBsAHkA')" ascii
    $s3 = "FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA==')" ascii
    $s4 = "[Parameter( ParameterSetName = 'ScheduledTaskAtLogon', Mandatory = $True )]" ascii
    $s5 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBBAHQATABvAGcAbwBuAA==')))" ascii
    $s6 = "[Parameter( ParameterSetName = 'PermanentWMIAtStartup', Mandatory = $True )]" fullword ascii
    $s7 = "FromBase64String('TQBlAHQAaABvAGQA')" ascii
    $s8 = "FromBase64String('VAByAGkAZwBnAGUAcgA=')" ascii
    $s9 = "[Runtime.InteropServices.CallingConvention]::Winapi," fullword ascii
  condition:
    ( uint16(0) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}