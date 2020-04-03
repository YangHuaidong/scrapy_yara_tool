rule telnet_cgi {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file telnet.cgi.txt"
    family = "None"
    hacker = "None"
    hash = "dee697481383052980c20c48de1598d1"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "W A R N I N G: Private Server"
    $s2 = "print \"Set-Cookie: SAVEDPWD=;\\n\"; # remove password cookie"
    $s3 = "$Prompt = $WinNT ? \"$CurrentDir> \" : \"[admin\\@$ServerName $C"
  condition:
    1 of them
}