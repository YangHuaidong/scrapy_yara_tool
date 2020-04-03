rule endor {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-12-05"
    description = "Rule to detect Endor family"
    email = "hugo.porcher@eset.com"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "BSD 2-Clause"
    reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $u = "user: %s"
    $p = "password: %s"
  condition:
    ssh_binary and $u and $p in (@u..@u+20)
}