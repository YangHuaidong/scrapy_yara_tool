rule IronTiger_dllshellexc2010 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "dllshellexc2010 Exchange backdoor + remote shell"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://goo.gl/T5fSJC"
    threatname = "None"
    threattype = "None"
  strings:
    $str1 = "Microsoft.Exchange.Clients.Auth.dll" nocase ascii wide
    $str2 = "Dllshellexc2010" nocase wide ascii
    $str3 = "Users\\ljw\\Documents" nocase wide ascii
    $bla1 = "please input path" nocase wide ascii
    $bla2 = "auth.owa" nocase wide ascii
  condition:
    (uint16(0) == 0x5a4d) and ((any of ($str*)) or (all of ($bla*)))
}