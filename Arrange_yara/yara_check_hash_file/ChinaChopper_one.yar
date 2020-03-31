rule ChinaChopper_one {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file one.asp
    family = None
    hacker = None
    hash = 6cd28163be831a58223820e7abe43d5eacb14109
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = ChinaChopper[one
    threattype = one.yar
  strings:
    $s0 = "<%eval request(" fullword ascii
  condition:
    filesize < 50 and all of them
}