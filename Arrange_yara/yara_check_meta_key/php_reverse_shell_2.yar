rule php_reverse_shell_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools - file php-reverse-shell.php"
    family = "None"
    hacker = "None"
    hash = "025db3c3473413064f0606d93d155c7eb5049c42"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://laudanum.inguardians.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii /* PEStudio Blacklist: strings */
    $s7 = "$shell = 'uname -a; w; id; /bin/sh -i';" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 10KB and all of them
}