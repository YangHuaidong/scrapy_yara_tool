rule WebShell_php_webshells_NGH {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "PHP Webshells Github Archive - file NGH.php"
    family = "None"
    hacker = "None"
    hash = "c05b5deecfc6de972aa4652cb66da89cfb3e1645"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<title>Webcommander at <?=$_SERVER[\"HTTP_HOST\"]?></title>" fullword
    $s2 = "/* Webcommander by Cr4sh_aka_RKL v0.3.9 NGH edition :p */" fullword
    $s5 = "<form action=<?=$script?>?act=bindshell method=POST>" fullword
    $s9 = "<form action=<?=$script?>?act=backconnect method=POST>" fullword
    $s11 = "<form action=<?=$script?>?act=mkdir method=POST>" fullword
    $s16 = "die(\"<font color=#DF0000>Login error</font>\");" fullword
    $s20 = "<b>Bind /bin/bash at port: </b><input type=text name=port size=8>" fullword
  condition:
    2 of them
}