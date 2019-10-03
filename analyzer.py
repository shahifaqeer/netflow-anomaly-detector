#!/usr/bin/python
import collections
import csv
import datetime
import ipaddr
import sys
# from blacklist_detector import Blacklist

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

_POPULAR_PORTS = {
    80: 'http',
    8080: 'http',
    443: 'ssl',
    22: 'ssh',
    53: 'dns',
    123: 'ntp',
    143: 'imap',
    993: 'imap-ssl'
}


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

        self.__safe_ips = set()
        self.__load_blacklist()

        self.__port_stats = {}
        self.__ip_stats = {}

    def __load_blacklist(self):
        with open('blacklist_ips.csv', 'r') as blacklistcsv:
            self.__blacklist = set(list(csv.reader(blacklistcsv))[0])
        print("load blacklist")

    def alert_ip_blacklist(self, flow):
        """Quick check for ip safety against static blacklist."""
        src_ip = flow.src_ip.exploded
        dst_ip = flow.dst_ip.exploded

        for ip_address, ip_type in [(src_ip, "source IP"), (dst_ip, "dest IP")]:
            if ip_address in self.__safe_ips:
                return False
            else:
                # this is a slow check
                if ip_address in self.__blacklist:
                    self.__alerts.append(Alert(name="Blacklisted " + ip_type + ": " + src_ip,
                                               evidence=[flow]))
                else:
                    self.__safe_ips.add(ip_address)

    def alert_port_activity(self, flow):
        """Log flow aggregates as indexed by port number.

        {dst_port: {IP1: True, IP2: False, ... }, total bytes, total connections, ...}
        src_ip, dst_ip: dict of {IP: first_time} where first_time is True if new IP
        bytes_up, bytes_dw: aggregate upload/download bytes for dst_port
        connections: total row entries seen for dst_port
        log first_usage in IP list and alert for first time use of a port
        """
        dport = flow.dst_port
        dst_ip = flow.dst_ip.exploded
        src_ip = flow.src_ip.exploded
        if dport not in self.__port_stats:
            self.__port_stats[dport] = {}
            self.__port_stats[dport]['bytes_dw'] = flow.dst_tx
            self.__port_stats[dport]['bytes_up'] = flow.src_tx
            self.__port_stats[dport]['connections'] = 1

            self.__port_stats[dport]['dst_ip'] = {}
            self.__port_stats[dport]['src_ip'] = {}
        else:
            self.__port_stats[dport]['bytes_dw'] += flow.dst_tx
            self.__port_stats[dport]['bytes_up'] += flow.src_tx
            self.__port_stats[dport]['connections'] += 1

        if dst_ip not in self.__port_stats[dport]['dst_ip']:
            self.__port_stats[dport]['dst_ip'][dst_ip] = True
            # self.__alerts.append(Alert(name="Unpopular port "+str(flow.dst_port)+" for dst_ip "+dst_ip,
            #                            evidence=[flow]))
        else:
            self.__port_stats[dport]['dst_ip'][dst_ip] = False
        if src_ip not in self.__port_stats[dport]['src_ip']:
            self.__port_stats[dport]['src_ip'][src_ip] = True
            # self.__alerts.append(Alert(name="Unpopular port "+str(flow.dst_port)+" for src_ip "+src_ip,
            #                            evidence=[flow]))
        else:
            self.__port_stats[dport]['src_ip'][dst_ip] = False

    def alert_ip_activity(self, flow):
        """Log flow aggregates as indexed by ip address.

        ip_to_port = {ip_address: [list of ports used]}
        Add alert if number of ports for IP exceeds threshold (simple)
        threshold calculated as average number of ports per IP address (simple)
        """
        pass

    def alert_flow_statistics(self, flow):
        """Aggregate flow counters every T seconds and derive features."""
        # TODO
        pass

    def process(self, flow):
        """
        Process a flow.

        1. Check src ip and dst ip against a blacklist set in memory
        2. Check dst_port and index first use for IP address + aggregate bytes

        :param Flow flow: a data flow record
        """
        self.__num_flows += 1

        # 1. Blacklist check
        self.alert_ip_blacklist(flow)

        # 2. Port check
        if flow.dst_port not in _POPULAR_PORTS:
            self.alert_port_activity(flow)
        self.alert_ip_activity(flow)

        # 3. Flow aggregator
        # TODO: agg every T sec and store flow info + extra features in memory

        # counter print
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
    # bl = Blacklist()    # create required offline blacklist and update it
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
