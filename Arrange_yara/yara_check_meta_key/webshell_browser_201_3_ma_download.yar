rule webshell_browser_201_3_ma_download {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, download.jsp"
    family = "None"
    hacker = "None"
    hash0 = "37603e44ee6dc1c359feb68a0d566f76"
    hash1 = "a7e25b8ac605753ed0c438db93f6c498"
    hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
    hash3 = "4cc68fa572e88b669bce606c7ace0ae9"
    hash4 = "fa87bbd7201021c1aefee6fcc5b8e25a"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "<small>jsp File Browser version <%= VERSION_NR%> by <a"
    $s3 = "else if (fName.endsWith(\".mpg\") || fName.endsWith(\".mpeg\") || fName.endsWith"
  condition:
    all of them
}