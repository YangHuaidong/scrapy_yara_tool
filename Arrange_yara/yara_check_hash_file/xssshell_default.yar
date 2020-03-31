rule xssshell_default {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file default.asp
    family = None
    hacker = None
    hash = d156782ae5e0b3724de3227b42fcaf2f
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = xssshell[default
    threattype = default.yar
  strings:
    $s3 = "If ProxyData <> \"\" Then ProxyData = Replace(ProxyData, DATA_SEPERATOR, \"<br />\")"
  condition:
    all of them
}