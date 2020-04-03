rule git_CVE_2017_9800_poc {
   meta:
      description = "Detects a CVE-2017-9800 exploitation attempt"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/mzbat/status/895811803325898753"
      date = "2017-08-11"
      score = 60
   strings:
      $s1 = "git clone ssh://-oProxyCommand=" ascii
      $s2 = "git clone http://-" ascii
      $s3 = "git clone https://-" ascii
   condition:
      filesize < 200KB and 1 of them
}