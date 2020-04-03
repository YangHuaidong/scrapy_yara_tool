rule git_CVE_2017_9800_poc {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-08-11"
    description = "Detects a CVE-2017-9800 exploitation attempt"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://twitter.com/mzbat/status/895811803325898753"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "git clone ssh://-oProxyCommand=" ascii
    $s2 = "git clone http://-" ascii
    $s3 = "git clone https://-" ascii
  condition:
    filesize < 200KB and 1 of them
}