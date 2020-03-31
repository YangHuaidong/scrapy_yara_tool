rule webshell_browser_201_3_ma_ma2_download {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, ma2.jsp, download.jsp
    family = 3
    hacker = None
    hash0 = 37603e44ee6dc1c359feb68a0d566f76
    hash1 = a7e25b8ac605753ed0c438db93f6c498
    hash2 = fb8c6c3a69b93e5e7193036fd31a958d
    hash3 = 4cc68fa572e88b669bce606c7ace0ae9
    hash4 = 4b45715fa3fa5473640e17f49ef5513d
    hash5 = fa87bbd7201021c1aefee6fcc5b8e25a
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    super_rule = 1
    threatname = webshell[browser]/201.3.ma.ma2.download
    threattype = browser
  strings:
    $s1 = "private static final int EDITFIELD_ROWS = 30;" fullword
    $s2 = "private static String tempdir = \".\";" fullword
    $s6 = "<input type=\"hidden\" name=\"dir\" value=\"<%=request.getAttribute(\"dir\")%>\""
  condition:
    2 of them
}