rule SUSP_Double_Base64_Encoded_Executable {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-10-29"
    description = "Detects an executable that has been encoded with base64 twice"
    family = "None"
    hacker = "None"
    hash1 = "1a172d92638e6fdb2858dcca7a78d4b03c424b7f14be75c2fd479f59049bc5f9"
    judge = "black"
    reference = "https://twitter.com/TweeterCyber/status/1189073238803877889"
    threatname = "None"
    threattype = "None"
  strings:
    $ = "VFZwVEFRR" ascii wide
    $ = "RWcFRBUU" ascii wide
    $ = "UVnBUQVFF" ascii wide
    $ = "VFZvQUFBQ" ascii wide
    $ = "RWb0FBQU" ascii wide
    $ = "UVm9BQUFB" ascii wide
    $ = "VFZxQUFBR" ascii wide
    $ = "RWcUFBQU" ascii wide
    $ = "UVnFBQUFF" ascii wide
    $ = "VFZwUUFBS" ascii wide
    $ = "RWcFFBQU" ascii wide
    $ = "UVnBRQUFJ" ascii wide
    $ = "VFZxUUFBT" ascii wide
    $ = "RWcVFBQU" ascii wide
    $ = "UVnFRQUFN" ascii wide
  condition:
    1 of them
}