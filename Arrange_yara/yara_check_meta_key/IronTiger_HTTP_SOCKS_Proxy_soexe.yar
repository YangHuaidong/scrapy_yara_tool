rule IronTiger_HTTP_SOCKS_Proxy_soexe {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Iron Tiger Toolset - HTTP SOCKS Proxy soexe"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://goo.gl/T5fSJC"
    threatname = "None"
    threattype = "None"
  strings:
    $str1 = "listen SOCKET error." nocase wide ascii
    $str2 = "WSAAsyncSelect SOCKET error." nocase wide ascii
    $str3 = "new SOCKETINFO error!" nocase wide ascii
    $str4 = "Http/1.1 403 Forbidden" nocase wide ascii
    $str5 = "Create SOCKET error." nocase wide ascii
  condition:
    uint16(0) == 0x5a4d and (3 of ($str*))
}