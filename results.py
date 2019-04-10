import logging.config
import numpy as np
import logging

logging.config.fileConfig("logging.conf")
logger = logging.getLogger('results')


class Results:

    def __init__(self):
        """
        `self.packets` is a dictionary of dictionaries as follows..
        {<pkt_id>: {'arrival': ___, 'departure': ___}, <pkt_id>: {...}, ...}
        """

        self.num_pkts_arrived = 0
        self.num_pkts_left = 0
        self.packets = {}

    def add_packet_arrival(self, pkt_id, time, malicious):
        self.packets[pkt_id] = {'arrival': time, 'departure': None, 'malicious': malicious}
        self.num_pkts_arrived += 1

    def add_packet_departure(self, pkt_id, time, malicious):
        if pkt_id in self.packets:
            self.packets[pkt_id]['departure'] = time
            self.packets[pkt_id]['malicious'] = malicious
        else:
            # Packet generator modules don't have arrivals
            self.packets[pkt_id] = {'arrival': None, 'departure': time, 'malicious': malicious}
        self.num_pkts_left += 1

    def get_scalar_results(self):
        return self.num_pkts_arrived, self.num_pkts_left

    def get_vector_results(self, add_to_log=True):

        pkt_stays = []
        for pkt in self.packets.values():
            if pkt['departure'] and pkt['arrival']:
                pkt_stays.append(pkt['departure'] - pkt['arrival'])

        if len(pkt_stays) > 0:
            mean_stay = np.mean(pkt_stays)
            mean_stay_str = "%.3f" % mean_stay
        else:
            mean_stay = None
            mean_stay_str = 'None'

        if add_to_log:
            logger.info("Packets arrived: %d" % self.num_pkts_arrived)
            logger.info("Packets left: %d" % self.num_pkts_left)
            logger.info("Mean packet stay: %s" % mean_stay_str)

        results = {'packet_id': [], 'arrival_time': [], 'departure_time': [], 'malicious': []}

        for packet_id, value in self.packets.items():
            results['packet_id'].append(packet_id)
            results['arrival_time'].append(value['arrival'])
            results['departure_time'].append(value['departure'])
            results['malicious'].append(value['malicious'])

            arrival_str = "%.3f" % value['arrival'] if value['arrival'] else 'None'
            departure_str = "%.3f" % value['departure'] if value['departure'] else 'None'
            if add_to_log:
                logger.info("%s : arrival: %s, departure: %s" % (packet_id, arrival_str, departure_str))

        return results


