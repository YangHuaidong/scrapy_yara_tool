rule webshell_404_data_suiyue {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - from files 404.jsp, data.jsp, suiyue.jsp
    family = suiyue
    hacker = None
    hash0 = 7066f4469c3ec20f4890535b5f299122
    hash1 = 9f54aa7b43797be9bab7d094f238b4ff
    hash2 = c93d5bdf5cf62fe22e299d0f2b865ea7
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    super_rule = 1
    threatname = webshell[404]/data.suiyue
    threattype = 404
  strings:
    $s3 = " sbCopy.append(\"<input type=button name=goback value=' \"+strBack[languageNo]+"
  condition:
    all of them
}