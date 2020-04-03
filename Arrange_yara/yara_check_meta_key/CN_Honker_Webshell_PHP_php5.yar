rule CN_Honker_Webshell_PHP_php5 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file php5.txt"
    family = "None"
    hacker = "None"
    hash = "0fd91b6ad400a857a6a65c8132c39e6a16712f19"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "else if(isset($_POST['reverse'])) { if(@ftp_login($connection,$user,strrev($user" ascii /* PEStudio Blacklist: strings */
    $s20 = "echo sr(35,in('hidden','dir',0,$dir).in('hidden','cmd',0,'mysql_dump').\"<b>\".$" ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x3f3c and filesize < 300KB and all of them
}