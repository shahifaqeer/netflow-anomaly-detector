#!/usr/bin/python
import collections
import csv
import datetime
import ipaddr
import sys
from blacklist_detector import Blacklist

_FLOW_FIELDS = [
    "ts",
    "ip_protocol",
    "state",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "src_tx",
    "dst_tx",
]


class Flow(collections.namedtuple("Flow", _FLOW_FIELDS)):
    __slots__ = ()

    @staticmethod
    def from_csv(e):
        """
        Factory method.

        Construct Flow instances from a CSV-representation of a flow.
        """
        return Flow(ts=datetime.datetime.strptime(e[0], "%Y-%m-%d %H:%M:%S"),
                    ip_protocol=e[1],
                    state=e[2],
                    src_ip=ipaddr.IPAddress(e[3]),
                    src_port=int(e[4]),
                    dst_ip=ipaddr.IPAddress(e[5]),
                    dst_port=int(e[6]),
                    src_tx=int(e[7]),
                    dst_tx=int(e[8]))


_ALERT_FIELDS = [
    "name",
    "evidence",
]

Alert = collections.namedtuple("Alert", _ALERT_FIELDS)


class Analyzer(object):

    def __init__(self):
        self.__num_flows = 0
        self.__alerts = []

        self.__blacklist = []
        self.__safe_ips = []
        self.__load_blacklist()

    def __load_blacklist(self):
        with open('blacklist_ips.csv', 'r') as blacklistcsv:
            self.__blacklist = list(csv.reader(blacklistcsv))
        print("load blacklist")

    def check_blacklist(self, ip_address):
        """quick check for ip safety"""
        if ip_address in self.__safe_ips:
            return False
        else:
            # this is a slow check
            if ip_address in self.__blacklist:
                return True
            else:
                self.__safe_ips.append(ip_address)
                return False

    def process(self, flow):
        """
        Process a flow.

        :param Flow flow: a data flow record
        """
        self.__num_flows += 1

        # 1. Blacklist check
        # populates list of safe ip addresses
        if self.check_blacklist(flow.src_ip.exploded):
            self.__alerts.append(Alert(name="Blacklisted source " + flow.src_ip.exploded,
                                       evidence=[flow]))
        if self.check_blacklist(flow.dst_ip.exploded):
            self.__alerts.append(Alert(name="Blacklisted destination " + flow.src_ip.exploded,
                                       evidence=[flow]))

        # 2. Flow open check

        # counter
        if (self.__num_flows % 10000) == 0:
            print("done flows", self.__num_flows)


    @property
    def alerts(self):
        """
        Return the alerts that were generated during the processing of flows.

        :return: a list of alerts
        :rtype: List[Alert]
        """
        return self.__alerts


def main(argv):
    analyzer = Analyzer()

    # setup blacklist file
    # bl = Blacklist()    # create required offline blacklist file for checks
    # del bl

    # pass input data stream as open("data.csv", "r") to csv.reader for testing
    with open('data.csv', 'r') as csvfile:
        #fin = csv.reader(sys.stdin)
        fin = csv.reader(csvfile)
        for e in fin:
            flow = Flow.from_csv(e)
            analyzer.process(flow)

        for alert in analyzer.alerts:
            print(alert.name)
            print("\n".join("\t{}".format(e) for e in alert.evidence))

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
