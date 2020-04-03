rule by063cli {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file by063cli.exe"
    family = "None"
    hacker = "None"
    hash = "49ce26eb97fd13b6d92a5e5d169db859"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "#popmsghello,are you all right?"
    $s4 = "connect failed,check your network and remote ip."
  condition:
    all of them
}