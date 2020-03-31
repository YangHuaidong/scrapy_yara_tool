# -*-coding:utf8 -*-
import os
import re

import yaratool

curdir2 = os.path.dirname(os.path.realpath(__file__))
yara = os.path.join(curdir2, "yara")
yara_file = os.path.join(curdir2, "yara_file")
yara_file_new = os.path.join(curdir2, "yara_file_new")
yara_check_file = os.path.join(curdir2, "yara_check_file")
yara_check_hash_file = os.path.join(curdir2, "yara_check_hash_file")
hash_name = "/home/kevin/Desktop/Arrange_yara/hash_name"


def classify():
    for rootpath, dirpath, filenames in os.walk(yara_file_new):
        for filename in filenames:
            filepath = os.path.join(rootpath, filename)
            with open(filepath, 'r')as f:
                f.seek(0)
                sigrules = f.read()
                sigrules.replace("：", ":")
                if sigrules.find('rule') > 1:
                    rules = yaratool.split(sigrules)
                    for rule in rules:
                        rule_name = os.path.join(yara_check_file, rule.name) + ".yar"
                        with open(rule_name, 'w+')as tmp:
                            tmp.write(rule.original)


def check_meta_key():
    for rootpath, dirpath, filenames in os.walk(yara_file):
        for filename in filenames:
            filepath = os.path.join(rootpath, filename)
            with open(filepath, 'r')as f:
                f.seek(0)
                rules = f.read()
            try:
                yr = yaratool.YaraRule(rules)
                if "judge" not in yr.metas.keys():
                    yr.metas['judge'] = 'unknown'
                if "threatname" not in yr.metas.keys():
                    yr.metas['threatname'] = 'None'
                if "threattype" not in yr.metas.keys():
                    yr.metas['threattype'] = 'None'
                if "family" not in yr.metas.keys():
                    yr.metas['family'] = 'None'
                if "hacker" not in yr.metas.keys():
                    yr.metas['hacker'] = 'None'
                if "comment" not in yr.metas.keys():
                    yr.metas['comment'] = 'None'
                if "date" not in yr.metas.keys():
                    yr.metas['date'] = 'None'
                if "reference" not in yr.metas.keys():
                    yr.metas['reference'] = 'None'
                if "description" not in yr.metas.keys():
                    yr.metas['description'] = 'None'

                yr.metas['author'] = 'Spider'

                # for key in yr.metas.keys():
                #     if key not in ["judge", "threatname", "threattype", "family", "hacker", "comment", "date",
                #                    "author", "reference", "description"]:
                # yr.metas.pop(key)
                yr.name = filename.split('.')[0]
                yr.metas['threatname'] = ((yr.name.replace("_", "[", 1)).replace("_", "]/", 1)).replace(
                    "_", ".")

                if '/' in yr.metas["threatname"]:
                    yr.metas['family'] = yr.metas["threatname"].split('/')[1].split('.')[1]

                yr.metas['threattype'] = filename.split("_")[1]

                new_rule1 = yr.normalize()
                rule_name = os.path.join(yara_check_file, filename)
                with open(rule_name, 'w+')as tmp:
                    tmp.write(new_rule1)
            except Exception as e:
                print(e)


key = ["hash", "hash0", "hash1"]


def check_meta_key_hash():
    for rootpath, dirpath, filenames in os.walk(yara_check_file):
        for filename in filenames:
            filepath = os.path.join(rootpath, filename)
            with open(filepath, 'r')as f:
                f.seek(0)
                rules = f.read()
            try:
                yr = yaratool.YaraRule(rules)
                for k in key:
                    if k in yr.metas.keys():
                        rule_name = os.path.join(yara_check_hash_file, filename)
                        with open(rule_name, 'w+')as tmp:
                            tmp.write(rules)
                        with open(hash_name, "a+")as n:
                            n.write(yr.metas[k])
            except Exception as e:
                print(e)


def check_hash_extract():
    for rootpath, dirpath, filenames in os.walk(yara_check_file):
        for filename in filenames:
            filepath = os.path.join(rootpath, filename)
            with open(filepath, 'r')as f:
                f.seek(0)
                rules = f.read()
            try:
                yr = yaratool.YaraRule(rules)
                for k in key:
                    if k in yr.metas.keys():
                        with open(hash_name, "a+")as n:
                            n.write(yr.metas[k] + "\n")
            except Exception as e:
                print(e)


if __name__ == '__main__':
    # check_meta_key()
    # check_meta_key_hash()
    check_hash_extract()
