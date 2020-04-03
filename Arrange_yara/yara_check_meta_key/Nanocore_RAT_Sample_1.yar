rule Nanocore_RAT_Sample_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-04-22"
    description = "Detetcs a certain Nanocore RAT sample"
    family = "None"
    hacker = "None"
    hash2 = "b7cfc7e9551b15319c068aae966f8a9ff563b522ed9b1b42d19c122778e018c8"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
    score = 75
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "TbSiaEdJTf9m1uTnpjS.n9n9M7dZ7FH9JsBARgK" fullword wide
    $x2 = "1EF0D55861681D4D208EC3070B720C21D885CB35" fullword ascii
    $x3 = "popthatkitty.Resources.resources" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 900KB and ( 1 of ($x*) ) ) or ( all of them )
}