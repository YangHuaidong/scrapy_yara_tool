rule RAT_VirusRat {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects VirusRAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/VirusRat"
    threatname = "None"
    threattype = "None"
  strings:
    $string0 = "virustotal"
    $string1 = "virusscan"
    $string2 = "abccba"
    $string3 = "pronoip"
    $string4 = "streamWebcam"
    $string5 = "DOMAIN_PASSWORD"
    $string6 = "Stub.Form1.resources"
    $string7 = "ftp://{0}@{1}" wide
    $string8 = "SELECT * FROM moz_logins" wide
    $string9 = "SELECT * FROM moz_disabledHosts" wide
    $string10 = "DynDNS\\Updater\\config.dyndns" wide
    $string11 = "|BawaneH|" wide
  condition:
    all of them
}