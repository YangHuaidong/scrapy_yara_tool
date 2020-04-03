rule CN_Honker_Webshell_PHP_php1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file php1.txt"
    family = "None"
    hacker = "None"
    hash = "c2f4b150f53c78777928921b3a985ec678bfae32"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s7 = "$sendbuf = \"site exec \".$_POST[\"SUCommand\"].\"\\r\\n\";" fullword ascii /* PEStudio Blacklist: strings */
    $s8 = "elseif(function_exists('passthru')){@ob_start();@passthru($cmd);$res = @ob_get_c" ascii /* PEStudio Blacklist: strings */
    $s18 = "echo Exec_Run($perlpath.' /tmp/spider_bc '.$_POST['yourip'].' '.$_POST['yourport" ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 621KB and all of them
}