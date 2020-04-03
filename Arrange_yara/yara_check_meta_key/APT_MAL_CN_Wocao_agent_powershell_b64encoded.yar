rule APT_MAL_CN_Wocao_agent_powershell_b64encoded {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Piece of Base64 encoded data from Agent CSharp version"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
    threatname = "None"
    threattype = "None"
  strings:
    $header = "LFNVT0hBBnVfVVJDSx0sU1VPSEEGdV9VUkNLCG9pHSxTVU9IQQZ1X1VSQ0sIZUlK"
  condition:
    all of them
}