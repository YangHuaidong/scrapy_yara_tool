rule webshell_201_3_ma_download {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - from files 201.jsp, 3.jsp, ma.jsp, download.jsp
    family = ma
    hacker = None
    hash0 = a7e25b8ac605753ed0c438db93f6c498
    hash1 = fb8c6c3a69b93e5e7193036fd31a958d
    hash2 = 4cc68fa572e88b669bce606c7ace0ae9
    hash3 = fa87bbd7201021c1aefee6fcc5b8e25a
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    super_rule = 1
    threatname = webshell[201]/3.ma.download
    threattype = 201
  strings:
    $s0 = "<input title=\"Upload selected file to the current working directory\" type=\"Su"
    $s5 = "<input title=\"Launch command in current directory\" type=\"Submit\" class=\"but"
    $s6 = "<input title=\"Delete all selected files and directories incl. subdirs\" class="
  condition:
    all of them
}