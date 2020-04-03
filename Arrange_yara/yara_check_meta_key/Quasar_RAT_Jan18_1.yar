rule Quasar_RAT_Jan18_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-01-29"
    description = "Detects Quasar RAT"
    family = "None"
    hacker = "None"
    hash1 = "0157b43eb3c20928b77f8700ad8eb279a0aa348921df074cd22ebaff01edaae6"
    hash2 = "24956d8edcf2a1fd26805ec58cfd1ee7498e1a59af8cc2f4b832a7ab34948c18"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-vermin-quasar-rat-custom-malware-used-ukraine/"
    threatname = "None"
    threattype = "None"
  strings:
    $a1 = "ping -n 20 localhost > nul" fullword wide
    $s2 = "HandleDownloadAndExecuteCommand" fullword ascii
    $s3 = "DownloadAndExecute" fullword ascii
    $s4 = "UploadAndExecute" fullword ascii
    $s5 = "ShellCommandResponse" fullword ascii
    $s6 = "Select * From Win32_ComputerSystem" fullword wide
    $s7 = "Process could not be started!" fullword wide
    $s8 = ".Core.RemoteShell" ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 600KB and $a1 and 3 of them
}