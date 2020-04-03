rule CN_disclosed_20180208_Mal5 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-02-08"
    description = "Detects malware from disclosed CN malware set"
    family = "None"
    hacker = "None"
    hash1 = "24c05cd8a1175fbd9aca315ec67fb621448d96bd186e8d5e98cb4f3a19482af4"
    hash2 = "05696db46144dab3355dcefe0408f906a6d43fced04cb68334df31c6dfd12720"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
    $s2 = "Server.exe" fullword ascii
    $s3 = "System.Windows.Forms.Form" fullword ascii
    $s4 = "Stub.Resources.resources" fullword ascii
    $s5 = "My.Computer" fullword ascii
    $s6 = "MyTemplate" fullword ascii
    $s7 = "Stub.My.Resources" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and all of them
}