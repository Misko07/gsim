from gsim.packets import PacketType

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
        self.num_normal_arrived = 0
        self.num_normal_left = 0
        self.num_malicious_arrived = 0
        self.num_malicious_left = 0
        self.num_permits_arrived = 0
        self.num_permits_left = 0
        self.num_negative_arrived = 0
        self.num_negative_left = 0  # Neg signals can only go out of Neg Signal Generator modules
        self.num_normal_removed = 0
        self.num_malicious_removed = 0
        self.num_permits_removed = 0
        self.packets = {}

    def add_packet_arrival(self, pkt_id, time, pkt_type):
        """ Update packet list and counters when a packet arrived at module

        :param pkt_id: str
        :param time: int current simulation time
        :param pkt_type: packets.PacketType - showing the type of packet
        :return: /
        """

        self.packets[pkt_id] = {
            'arrival': time,
            'departure': None,
            'removal': None,
            'normal': pkt_type == PacketType.NORMAL,
            'malicious': pkt_type == PacketType.MALICIOUS,
            'permit': pkt_type == PacketType.PERMIT,
            'negative': pkt_type == PacketType.NEG_SIGNAL
        }

        if pkt_type == PacketType.PERMIT:
            self.num_permits_arrived += 1
        elif pkt_type == PacketType.NEG_SIGNAL:
            self.num_negative_arrived += 1
        else:
            self.num_pkts_arrived += 1

        if pkt_type == PacketType.MALICIOUS:
            self.num_malicious_arrived += 1
        else:
            self.num_normal_arrived += 1

        assert(self.num_pkts_arrived == self.num_malicious_arrived + self.num_normal_arrived)

    def add_packet_departure(self, pkt_id, time, pkt_type):
        """ Update packet list and counters when a packet left a module

        :param pkt_id: str
        :param time: int, current sim time
        :param pkt_type: packets.PacketType - showing the type of packet
        :return: /
        """

        if pkt_id in self.packets:
            self.packets[pkt_id]['departure'] = time
        else:
            # Packet generator modules don't have arrivals
            self.packets[pkt_id] = {
                'arrival': None,
                'departure': time,
                'removal': None,
                'malicious': pkt_type == PacketType.MALICIOUS,
                'negative': pkt_type == PacketType.NEG_SIGNAL,
                'permit': pkt_type == PacketType.PERMIT
            }

        if pkt_type == PacketType.PERMIT:
            self.num_permits_left += 1
        elif pkt_type == PacketType.NEG_SIGNAL:
            self.num_negative_left += 1
        else:
            self.num_pkts_left += 1

        if pkt_type == PacketType.MALICIOUS:
            self.num_malicious_left += 1
        else:
            self.num_normal_left += 1

        assert(self.num_pkts_left == self.num_malicious_left + self.num_normal_left)

    def add_packet_removal(self, pkt_id, time, pkt_type):
        """ Record a packet removal by an arrival of a negative signal to the module.

        :param pkt_id: int, the id of removed packet
        :param time: int, time of removal
        :param pkt_type: PacketType, type of removed packet
        :return: /
        """

        if pkt_id in self.packets and self.packets[pkt_id]['departure'] is None:
            self.packets[pkt_id]['removal'] = time
        else:
            raise RuntimeError("Trying to remove a packet which is not in the current module.")

        if pkt_type == PacketType.MALICIOUS:
            self.num_malicious_removed += 1
        elif pkt_type == PacketType.NORMAL:
            self.num_normal_removed += 1
        elif pkt_type == PacketType.PERMIT:
            self.num_permits_removed += 1

    def get_scalar_results(self):
        """ Get a summary of simulation statistics (scalars)

        :return: tuple of multiple scalar values
        """

        # Calculate waittime for normal and permit packets
        pkt_stays_normal = []
        pkt_stays_permit = []
        for pkt in self.packets.values():
            if pkt['departure'] and pkt['arrival']:
                if not (pkt['malicious'] or pkt['negative'] or pkt['permit']):
                    pkt_stays_normal.append(pkt['departure'] - pkt['arrival'])
                elif pkt['permit']:
                    pkt_stays_permit.append(pkt['departure'] - pkt['arrival'])

        mean_stay_normal = np.mean(pkt_stays_normal) if len(pkt_stays_normal) else None
        mean_stay_permit = np.mean(pkt_stays_permit) if len(pkt_stays_permit) else None

        return self.num_pkts_arrived, self.num_pkts_left, self.num_normal_arrived, self.num_normal_left, \
            self.num_malicious_arrived, self.num_malicious_left, self.num_permits_arrived, self.num_permits_left, \
            self.num_negative_arrived, self.num_negative_left, self.num_normal_removed, self.num_malicious_removed, \
            self.num_permits_removed, mean_stay_normal, mean_stay_permit

    def get_vector_results(self):
        """ Get a summary of time-series (vector) results

        :return: dict containing data for every packet that arrived in the module
        """

        results = {'packet_id': [], 'arrival_time': [], 'departure_time': [], 'removal_time': [], 'malicious': [],
                   'negative': [], 'permit': []}

        for packet_id, value in self.packets.items():
            results['packet_id'].append(packet_id)
            results['arrival_time'].append(value['arrival'])
            results['departure_time'].append(value['departure'])
            results['removal_time'].append(value['removal'])
            results['malicious'].append(value['malicious'])
            results['negative'].append(value['negative'])
            results['permit'].append(value['permit'])

        return results


