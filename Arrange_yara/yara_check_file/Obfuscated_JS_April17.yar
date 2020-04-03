rule Obfuscated_JS_April17 {
   meta:
      description = "Detects cloaked Mimikatz in JS obfuscation"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-04-21"
   strings:
      $s1 = "\";function Main(){for(var "  ascii
      $s2 = "=String.fromCharCode(parseInt(" ascii
      $s3 = "));(new Function(" ascii
   condition:
      filesize < 500KB and all of them
}