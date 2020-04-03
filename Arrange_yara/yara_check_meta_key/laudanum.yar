rule laudanum {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools - file laudanum.php"
    family = "None"
    hacker = "None"
    hash = "fd498c8b195967db01f68776ff5e36a06c9dfbfe"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://laudanum.inguardians.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "public function __activate()" fullword ascii
    $s2 = "register_activation_hook(__FILE__, array('WP_Laudanum', 'activate'));" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 5KB and all of them
}