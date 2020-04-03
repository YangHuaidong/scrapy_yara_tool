rule Casper_SystemInformation_Output {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/06"
    description = "Casper French Espionage Malware - System Info Output - http://goo.gl/VRJNLo"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/VRJNLo"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $a0 = "***** SYSTEM INFORMATION ******"
    $a1 = "***** SECURITY INFORMATION ******"
    $a2 = "Antivirus: "
    $a3 = "Firewall: "
    $a4 = "***** EXECUTION CONTEXT ******"
    $a5 = "Identity: "
    $a6 = "<CONFIG TIMESTAMP="
  condition:
    all of them
}