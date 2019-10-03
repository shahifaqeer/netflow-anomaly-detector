#!/usr/bin/env python
# Name: blacklist_update.py
# By: Sarthak Grover
# Date: 2019-10-2
# ----------------------------
# download a blacklist of IP addresses
# check ipaddr in blacklist
# can be easily extended to include DNS if needed


import requests
import os
import sys
import csv


BLACKLIST_URLS = [
    ("https://rules.emergingthreats.net/blockrules/compromised-ips.txt", 'ip', 'csv'),
    #("http://reputation.alienvault.com/reputation.data", 'ip', 'split#0'),
]

blacklist_ips_savefile = "blacklist_ips.csv"


class Blacklist(object):
    """
    Creates an IP blacklist from a list of popular blacklist IP urls
    Checks ip address in blacklist
    Updates blacklist
    """
    def __init__(self):
        """
        Initialize blacklist dictionary
        load from saved csv or download
        """
        self.__blacklist = []
        if os.path.isfile(blacklist_ips_savefile):
            with open(blacklist_ips_savefile, "r") as csvfile:
                fin = csv.reader(csvfile)
                self.__blacklist = list(fin)

        #print("update blacklist")
        #self.__update()

    def __update(self):
        """
        update current blacklist from url and save new blacklist as csv
        """
        for (url, list_type, list_format) in BLACKLIST_URLS:
            try:
                resp = requests.get(url)
                print("get blacklist from "+url)
            except requests.exceptions.RequestException as e:
                print(e)
                continue

            # response parse based on what url returns - ip or dns/direct parse or not
            if list_type == 'ip':
                if list_format == 'csv':
                    # directly strip and split to list
                    ips = resp.text.strip().split("\n")
                    # check if any additions
                    for ip in ips:
                        if ip not in self.__blacklist:
                            self.__blacklist.append(ip)
                elif list_format == 'split#0':
                    data = resp.text.strip().split("\n")
                    # need to get first elem in each row
                    for row in data:
                        ip = row.split("#")[0]
                        if ip not in self.__blacklist:
                            self.__blacklist.append(ip)


        # save current blacklist
        with open(blacklist_ips_savefile, "w") as csvfile:
            fout = csv.writer(csvfile)
            fout.writerow(self.__blacklist)
            print("Save updated blacklist")

        return

    def check_ip(self, ipaddr_str):
        """check if ipaddr in blacklist"""
        if ipaddr_str in self.__blacklist:
            return True
        return False

    def get_ip_info(self, ipaddr_str):
        """API to get info on ipaddr - name, location, resolver, etc."""
        # TODO: return ip name
        return ipaddr_str


def main():

    blacklist = Blacklist()

    for ip in ["192.168.1.1", "104.197.185.83", "46.148.20.25"]:
        print("Check IP "+ip+": "),
        print(blacklist.check_ip(ip))


if __name__ == "__main__":
    main()
