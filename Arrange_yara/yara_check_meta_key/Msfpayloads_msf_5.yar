rule Msfpayloads_msf_5 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-09"
    description = "Metasploit Payloads - file msf.msi"
    family = "None"
    hacker = "None"
    hash1 = "7a6c66dfc998bf5838993e40026e1f400acd018bde8d4c01ef2e2e8fba507065"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "required to install Foobar 1.0." fullword ascii
    $s2 = "Copyright 2009 The Apache Software Foundation." fullword wide
    $s3 = "{50F36D89-59A8-4A40-9689-8792029113AC}" fullword ascii
  condition:
    all of them
}