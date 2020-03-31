rule CVE_2017_8759_WSDL_in_RTF {
  meta:
    author = Spider
    comment = None
    date = 2017-09-15
    description = Detects malicious RTF file related CVE-2017-8759
    family = WSDL
    hacker = None
    judge = unknown
    reference = https://twitter.com/xdxdxdxdoa/status/908665278199996416
    threatname = CVE[2017]/8759.WSDL.in.RTF
    threattype = 2017
  strings:
    $doc = "d0cf11e0a1b11ae1"
    $obj = "\\objupdate"
    $wsdl = "7700730064006c003d00" nocase
    $http1 = "68007400740070003a002f002f00" nocase
    $http2 = "680074007400700073003a002f002f00" nocase
    $http3 = "6600740070003a002f002f00" nocase
  condition:
    RTFFILE and $obj and $doc and $wsdl and 1 of ($http*)
}