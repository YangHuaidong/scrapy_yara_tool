rule wh_bindshell_py {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file wh_bindshell.py.txt"
    family = "None"
    hacker = "None"
    hash = "fab20902862736e24aaae275af5e049c"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "#Use: python wh_bindshell.py [port] [password]"
    $s2 = "python -c\"import md5;x=md5.new('you_password');print x.hexdigest()\"" fullword
    $s3 = "#bugz: ctrl+c etc =script stoped=" fullword
  condition:
    1 of them
}