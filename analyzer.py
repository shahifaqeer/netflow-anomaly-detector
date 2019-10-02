#!/usr/bin/python
import collections
import csv
import datetime
import ipaddr
import sys


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

    def process(self, flow):
        """
        Process a flow.

        :param Flow flow: a data flow record
        """
        self.__num_flows += 1

        # TODO: implement your detection technique here.
        #
        # What follows is a trivial example of how alerts can be built - remove it :-)
        if flow.dst_ip.exploded == "188.209.49.135":
            self.__alerts.append(Alert(name="Nebula IP address",
                                       evidence=[flow]))

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

    fin = csv.reader(sys.stdin)
    for e in fin:
        flow = Flow.from_csv(e)
        analyzer.process(flow)

    for alert in analyzer.alerts:
        print(alert.name)
        print("\n".join("\t{}".format(e) for e in alert.evidence))

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
