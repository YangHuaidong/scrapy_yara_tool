rule CN_Honker_Webshell_Tuoku_script_xx {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file xx.php"
    family = "None"
    hacker = "None"
    hash = "2f39f1d9846ae72fc673f9166536dc21d8f396aa"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$mysql.=\"insert into `$table`($keys) values($vals);\\r\\n\";" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "$mysql_link=@mysql_connect($mysql_servername , $mysql_username , $mysql_password" ascii /* PEStudio Blacklist: strings */
    $s16 = "mysql_query(\"SET NAMES gbk\");" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 2KB and all of them
}