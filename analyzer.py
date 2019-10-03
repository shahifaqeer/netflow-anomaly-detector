#!/usr/bin/python
import collections
import csv
import datetime
import ipaddr
import sys
import numpy as np

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
    993: 'imap-ssl',
}

_INTERESTING_PORTS = {
    0: 'reserved',
    81: 'Tor',
    82: 'Tor-control',
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
        self.__num_ports_average = 5

    def __load_blacklist(self):
        with open('blacklist_ips.csv', 'r') as blacklistcsv:
            self.__blacklist = set(list(csv.reader(blacklistcsv))[0])
        print("load blacklist")

    def alert_basic_checks(self, flow):
        """Check for local gateway, malformed packets, and packets of size < min length"""

        src_ip = flow.src_ip.exploded
        dst_ip = flow.dst_ip.exploded

        if flow.dst_port in _INTERESTING_PORTS:
            self.__alerts.append(Alert(name="Using interesting port number "+str(flow.dst_port),
                                       evidence=[flow]))

        if (src_ip is "0.0.0.0" and dst_ip is "255.255.255.255") or\
                (src_ip is not "0.0.0.0" and dst_ip is "255.255.255.255"):
            self.__alerts.append(Alert(name="Malformed DHCP or local gateway flow",
                                       evidence=[flow]))
            # TODO also add check for ip_protocol == udp and connection state

        if flow.src_tx == 0 and flow.dst_tx == 0:
            # TODO: confirm if src_tx and dst_tx include header lengths for ACKs and SYNs or only data
            # TODO: also check with connection state (closed, closing, established, reset)
            # self.__alerts.append(Alert(name="0 byte transferred", evidence=[flow]))
            pass

        if flow.src_ip.is_private and flow.dst_ip.is_private:
            # self.__alerts.append(Alert(name="Capturing network private flows", evidence=[flow]))
            pass

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

        ip_to_port = {ip_address1: {'dst_port': [unique list of ports used], 'num_ports': int, 'bytes_dw': sum }, ... }
        for src_ip: bytes_dw is dst_tx and bytes_up is src_tx
        for dst_ip: bytes_dw is src_tx and bytes_up is dst_tx TODO: should we save these separately instead?
        function calculates the average number of ports per IP address (simple)
        TODO: add std calculation too or model mean, std number of ports for each ip address instead
        Add alert if number of ports for IP exceeds threshold (v. simple)
        - this obviously creates too many alerts initially but should stabilize later
        - Static median number of ports from current dataset is much better than mean
        If already alerted for ipaddr, no need to add for now
        """
        def __calculate_port_alert_threshold(ip_stats):
            """Calculate average number of ports for all IPs in list

            Offline analysis on data: df.groupby(['src_ip'])['dst_port'].unique().apply(lambda x: len(x)).mean()
             mean number of unique ports for srcip = 4.55
             mean number of unique ports for dstip = 2.24
             median number of unique ports for srcip = 1.5
             median number of unique ports for dstip = 1
             max (avg, std) reaches to (3.5, 19.2)
             offline hist shows 2 categories: lower than 25 and more than 150 unique ports
            """
            num_unique_ports_per_ip = [v['num_ports'] for v in ip_stats.values()]

            # TODO generally median and median-absolute-deviation is much better than (mean,std) for outlier detection
            # https://stats.stackexchange.com/questions/121071/can-we-use-leave-one-out-mean-and-standard-deviation-to-reveal-the-outliers

            # TODO: use separate thresholds for srcip and dstip based on hist of number of unique ports
            avg = np.mean(num_unique_ports_per_ip)
            std = np.std(num_unique_ports_per_ip)
            perc90 = np.percentile(num_unique_ports_per_ip, 90)
            print(avg,std,perc90)
            return perc90

        dport = flow.dst_port
        dst_ip = flow.dst_ip.exploded
        src_ip = flow.src_ip.exploded

        for (ip_addr, direction) in [(src_ip, 0), (dst_ip, 1)]:
            if ip_addr not in self.__ip_stats:
                self.__ip_stats[ip_addr] = {}
                self.__ip_stats[ip_addr]['bytes_dw'] = 0
                self.__ip_stats[ip_addr]['bytes_up'] = 0
                self.__ip_stats[ip_addr]['connections'] = 0
                self.__ip_stats[ip_addr]['num_ports'] = 0
                self.__ip_stats[ip_addr]['dst_port'] = []
                self.__ip_stats[ip_addr]['num_ports_alert'] = False
            else:
                if direction is 1:
                    self.__ip_stats[ip_addr]['bytes_dw'] += flow.src_tx
                    self.__ip_stats[ip_addr]['bytes_up'] += flow.dst_tx
                else:
                    self.__ip_stats[ip_addr]['bytes_dw'] += flow.dst_tx
                    self.__ip_stats[ip_addr]['bytes_up'] += flow.src_tx
            self.__ip_stats[ip_addr]['connections'] += 1

            if dport not in self.__ip_stats[ip_addr]['dst_port']:
                self.__ip_stats[ip_addr]['num_ports'] += 1
                self.__ip_stats[ip_addr]['dst_port'].append(dport)
                self.__num_ports_average = __calculate_port_alert_threshold(self.__ip_stats)

            # if 3 times more than avg then definitely alert (simple)
            if self.__ip_stats[ip_addr]['num_ports'] > self.__num_ports_average and dport not in _POPULAR_PORTS:
                if not self.__ip_stats[ip_addr]['num_ports_alert']:
                    self.__alerts.append(Alert(name="IP " + ip_addr + " using too many ports: "
                                                    + str(len(self.__ip_stats[ip_addr]['dst_port'])), evidence=[flow]))
                    self.__ip_stats[ip_addr]['num_ports_alert'] = True
            if self.__ip_stats[ip_addr]['num_ports'] > 100:
                self.__alerts.append(Alert(name="IP " + ip_addr + " using more than 100 ports: "
                                                + str(len(self.__ip_stats[ip_addr]['dst_port'])), evidence=[flow]))

    def alert_flow_statistics(self, flow):
        """Aggregate flow counters every T=5 seconds"""
        # TODO
        pass

    def alert_clustering(self, flow):
        """
        Cluster flows based on derived features.

        Unsupervised learning to categorize based on similarity and density.
        Can use PCA for further dimensional reduction.
        Strings should be replaced with categorical features.
        Dependency: pandas, sklearn.
        """
        # TODO
        pass

    def alert_rnn_model(self, flow):
        """
        Predict anomaly based on LSTM network.

        Requires large training data as input.
        """
        pass

    def process(self, flow):
        """
        Process a flow.

        0. Check basics: packet lengths, local IPs, connection state, protocols, etc.
        1. Check src ip and dst ip against a blacklist set in memory
        2. Check dst_port and index first use for IP address + aggregate bytes

        :param Flow flow: a data flow record
        """
        self.__num_flows += 1

        # 0. Basic checks
        self.alert_basic_checks(flow)

        # 1. Blacklist check
        self.alert_ip_blacklist(flow)

        # 2. Port check
        if flow.dst_port not in _POPULAR_PORTS:
            self.alert_port_activity(flow)

        # 3. IP check
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

    print("Total Number of Alerts: "+str(len(analyzer.alerts)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
