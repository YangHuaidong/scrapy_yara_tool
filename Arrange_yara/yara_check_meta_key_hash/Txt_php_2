rule Txt_php_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-14"
    description = "Chinese Hacktool Set - Webshells - file php.html"
    family = "None"
    hacker = "None"
    hash = "a7d5fcbd39071e0915c4ad914d31e00c7127bcfc"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "function connect($dbhost, $dbuser, $dbpass, $dbname='') {" fullword ascii
    $s2 = "scookie('loginpass', '', -86400 * 365);" fullword ascii
    $s3 = "<title><?php echo $act.' - '.$_SERVER['HTTP_HOST'];?></title>" fullword ascii
    $s4 = "Powered by <a title=\"Build 20130112\" href=\"http://www.4ngel.net\" target=\"_b" ascii
    $s5 = "formhead(array('title'=>'Execute Command', 'onsubmit'=>'g(\\'shell\\',null,this." ascii
    $s6 = "secparam('IP Configurate',execute('ipconfig -all'));" fullword ascii
    $s7 = "secparam('Hosts', @file_get_contents('/etc/hosts'));" fullword ascii
    $s8 = "p('<p><a href=\"http://w'.'ww.4'.'ng'.'el.net/php'.'sp'.'y/pl'.'ugin/\" target=" ascii
  condition:
    filesize < 100KB and 4 of them
}