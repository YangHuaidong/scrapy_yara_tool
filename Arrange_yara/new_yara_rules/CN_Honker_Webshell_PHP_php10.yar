rule CN_Honker_Webshell_PHP_php10 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file php10.txt"
    family = "None"
    hacker = "None"
    hash = "3698c566a0ae07234c8957112cdb34b79362b494"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "dumpTable($N,$M,$Hc=false){if($_POST[\"format\"]!=\"sql\"){echo\"\\xef\\xbb\\xbf" ascii /* PEStudio Blacklist: strings */
    $s2 = "';if(DB==\"\"||!$od){echo\"<a href='\".h(ME).\"sql='\".bold(isset($_GET[\"sql\"]" ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 600KB and all of them
}