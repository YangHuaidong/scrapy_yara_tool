rule eBayId_index3 {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file index3.php
    family = None
    hacker = None
    hash = 0412b1e37f41ea0d002e4ed11608905f
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = eBayId[index3
    threattype = index3.yar
  strings:
    $s8 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"You"
  condition:
    all of them
}