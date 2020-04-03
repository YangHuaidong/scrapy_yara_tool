rule apt_ProjectSauron_encryption {
  meta:
    author = "Spider"
    comment = "None"
    copyright = "Kaspersky Lab"
    date = "None"
    description = "Rule to detect ProjectSauron string encryption"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://securelist.com/blog/"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $a1 = {81??02AA02C175??8B??0685}
    $a2 = { 91 8d 9a 94 cd cc 93 9a 93 93 9b d1 8b 9a b8 de 9c 90 8d af 8d 9b 9b be 8c 8c 9a ff }
    $a3 = {803E225775??807E019F75??807E02BE75??807E0309}
  condition:
    filesize < 5000000 and
    any of ($a*)
}