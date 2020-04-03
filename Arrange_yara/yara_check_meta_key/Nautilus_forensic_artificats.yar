rule Nautilus_forensic_artificats {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017/11/23"
    description = "Rule for detection of Nautilus related strings"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $ = "App_Web_juvjerf3.dll" fullword ascii
    $ = "App_Web_vcplrg8q.dll" fullword ascii
    $ = "ar_all2.txt" fullword ascii
    $ = "ar_sa.txt" fullword ascii
    $ = "Convert.FromBase64String(temp[1])" fullword ascii
    $ = "D68gq#5p0(3Ndsk!" fullword ascii
    $ = "dcomnetsrv" fullword ascii
    $ = "ERRORF~1.ASP" fullword ascii
    $ = "intelliAdminRpc" fullword ascii
    $ = "J8fs4F4rnP7nFl#f" fullword ascii
    $ = "Msnb.exe" fullword ascii
    $ = "nautilus-service.dll"
    $ = "Neuron_service" fullword ascii
    $ = "owa_ar2.bat" fullword ascii
    $ = "payload.x64.dll.system" fullword ascii
    $ = "service.x64.dll.system" fullword ascii
  condition:
    1 of them
}