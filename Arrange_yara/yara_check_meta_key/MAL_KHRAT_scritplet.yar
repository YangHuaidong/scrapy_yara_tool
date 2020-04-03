rule MAL_KHRAT_scritplet {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-08-31"
    description = "Rule derived from KHRAT scriptlet"
    family = "None"
    hacker = "None"
    hash1 = "cdb9104636a6f7c6018fe99bc18fb8b542689a84c23c10e9ea13d5aa275fd40e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://researchcenter.paloaltonetworks.com/2017/08/unit42-updated-khrat-malware-used-in-cambodia-attacks/"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "http.open \"POST\", \"http://update.upload-dropbox[.]com/docs/tz/GetProcess.php\",False,\"\",\"\" " fullword ascii
    $x2 = "Process=Process & Chr(32) & Chr(32) & Chr(32) & Obj.Description" fullword ascii
    $s1 = "http.SetRequestHeader \"Content-Type\", \"application/json\" " fullword ascii
    $s2 = "Dim http,WMI,Objs,Process" fullword ascii
    $s3 = "Set Objs=WMI.InstancesOf(\"Win32_Process\")" fullword ascii
    $s4 = "'WScript.Echo http.responseText " fullword ascii
  condition:
    uint16(0) == 0x3f3c and filesize < 1KB and ( 1 of ($x*) or 4 of them )
}