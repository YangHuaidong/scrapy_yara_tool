rule Antichat_Socks5_Server_php_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file Antichat Socks5 Server.php.php.txt
    family = php
    hacker = None
    hash = cbe9eafbc4d86842a61a54d98e5b61f1
    judge = unknown
    reference = None
    threatname = Antichat[Socks5]/Server.php.php
    threattype = Socks5
  strings:
    $s0 = "$port = base_convert(bin2hex(substr($reqmessage[$id], 3+$reqlen+1, 2)), 16, 10);" fullword
    $s3 = "#   [+] Domain name address type"
    $s4 = "www.antichat.ru"
  condition:
    1 of them
}