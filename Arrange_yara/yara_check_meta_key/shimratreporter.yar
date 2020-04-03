rule shimratreporter {
  meta:
    author = "Spider"
    comment = "None"
    date = "20/11/2015"
    description = "Detects ShimRatReporter"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $IpInfo = "IP-INFO"
    $NetworkInfo = "Network-INFO"
    $OsInfo = "OS-INFO"
    $ProcessInfo = "Process-INFO"
    $BrowserInfo = "Browser-INFO"
    $QueryUserInfo = "QueryUser-INFO"
    $UsersInfo = "Users-INFO"
    $SoftwareInfo = "Software-INFO"
    $AddressFormat = "%02X-%02X-%02X-%02X-%02X-%02X"
    $proxy_str = "(from environment) = %s"
    $netuserfun = "NetUserEnum"
    $networkparams = "GetNetworkParams"
  condition:
    all of them
}