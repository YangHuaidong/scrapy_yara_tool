rule IMPLANT_4_v10 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-10"
    description = "BlackEnergy / Voodoo Bear Implant by APT28"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $ = { a1 b0 5c 72 }
    $ = { eb 3d 03 84 }
    $ = { 6f 45 59 4e }
    $ = { 71 81 5a 4e }
    $ = { d5 b0 3e 72 }
    $ = { 6b 43 59 4e }
    $ = { f5 72 99 3d }
    $ = { 66 5d 9d c0 }
    $ = { 0b e7 a7 5a }
    $ = { f3 74 43 c5 }
    $ = { a2 a4 74 bb }
    $ = { 97 de ec 67 }
    $ = { 7e 0c b0 78 }
    $ = { 9c 96 78 bf }
    $ = { 4a 37 a1 49 }
    $ = { 86 67 41 6b }
    $ = { 0a 37 5b a4 }
    $ = { dc 50 5a 8d }
    $ = { 02 f1 f8 08 }
    $ = { 2c 81 97 12 }
  condition:
    uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550 and 15 of them
}