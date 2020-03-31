rule users_list {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file users_list.php
    family = None
    hacker = None
    hash = 6fba1a1a607198ed232405ccbebf9543037a63ef
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = users[list
    threattype = list.yar
  strings:
    $s0 = "<a href=\"users_create.php\">Create User</a>" fullword ascii
    $s7 = "$skiplist = array('##MS_AgentSigningCertificate##','NT AUTHORITY\\NETWORK SERVIC" ascii
    $s11 = "&nbsp;<b>Default DB</b>&nbsp;" fullword ascii
  condition:
    filesize < 12KB and all of them
}