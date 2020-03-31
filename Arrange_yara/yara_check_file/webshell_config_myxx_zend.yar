rule webshell_config_myxx_zend {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - from files config.jsp, myxx.jsp, zend.jsp
    family = zend
    hacker = None
    hash0 = d44df8b1543b837e57cc8f25a0a68d92
    hash1 = e0354099bee243702eb11df8d0e046df
    hash2 = 591ca89a25f06cf01e4345f98a22845c
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    super_rule = 1
    threatname = webshell[config]/myxx.zend
    threattype = config
  strings:
    $s3 = ".println(\"<a href=\\\"javascript:alert('You Are In File Now ! Can Not Pack !');"
  condition:
    all of them
}