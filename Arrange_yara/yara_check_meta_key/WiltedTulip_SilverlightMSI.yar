rule WiltedTulip_SilverlightMSI {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-07-23"
    description = "Detects powershell tool call Get_AD_Users_Logon_History used in Operation Wilted Tulip"
    family = "None"
    hacker = "None"
    hash1 = "c75906dbc3078ff81092f6a799c31afc79b1dece29db696b2ecf27951a86a1b2"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://www.clearskysec.com/tulip"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = ".\\Get_AD_Users_Logon_History.ps1 -MaxEvent" fullword ascii
    $x2 = "if ((Resolve-dnsname $_.\"IP Address\" -Type PTR -TcpOnly -DnsOnly -ErrorAction \"SilentlyContinue\").Type -eq \"PTR\")" fullword ascii
    $x3 = "$Client_Name = (Resolve-dnsname $_.\"IP Address\" -Type PTR -TcpOnly -DnsOnly).NameHost  " fullword ascii
    $x4 = "########## Find the Computer account in AD and if not found, throw an exception ###########" fullword ascii
  condition:
    ( filesize < 20KB and 1 of them )
}