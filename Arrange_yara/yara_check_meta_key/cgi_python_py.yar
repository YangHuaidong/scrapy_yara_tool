rule cgi_python_py {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file cgi-python.py.txt"
    family = "None"
    hacker = "None"
    hash = "0a15f473e2232b89dae1075e1afdac97"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "a CGI by Fuzzyman"
    $s1 = "\"\"\"+fontline +\"Version : \" + versionstring + \"\"\", Running on : \"\"\" + "
    $s2 = "values = map(lambda x: x.value, theform[field])     # allows for"
  condition:
    1 of them
}