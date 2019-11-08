from gsim.results import Results
from gsim.packets import Packet, PacketType
from gsim.events import Event, EventType
from gsim.gsim_utils import choose_output, create_arrival_event
from gsim.configs import ROOT_DIR

import numpy as np
import logging


logging.config.fileConfig(ROOT_DIR + "/logging.conf")
logger = logging.getLogger('generators')


class Source:
    """
    A generator for data Packets (normal or malicious)
    """

    def __init__(self, rate, outputs=None, distribution='Poisson', attack_prob=0, sim=None, model=None, name=None):
        """
        Constructor

        :param rate: A float for packet generation rate
        :param outputs: A list of dictionaries {'module': ..., 'prob': ...}
        :param distribution: A string. Currently only 'Poisson' is supported
        """

        self.rate = rate
        self.outputs = outputs
        self.distribution = distribution
        self.attack_prob = attack_prob
        self.sim = sim
        self.model = model
        self.name = name
        self.results = Results()

    def _register_with_model(self, model):
        self.model = model

    def _register_with_sim(self, sim):
        self.sim = sim

    def generate_packet(self):
        """
        Generate a single packet in a time-slot coming from some distribution.
        :return: /
        """

        # Todo: some of the events stuff below might need to be moved to simulation.process_event

        # Timestamp of next packet generation
        noise = (np.random.rand() - 0.5)/20  # added noise
        timestamp = self.sim._get_time() + np.random.poisson(1 / self.rate, 1)[0] + noise

        # Create packet
        malicious = np.random.choice([True, False], 1, p=[self.attack_prob, 1 - self.attack_prob])[0]
        packet = Packet(
            ptype=PacketType.MALICIOUS if malicious else PacketType.NORMAL,
            active=True,
            module_id=id(self),
            generation_time=timestamp
        )

        # Register packet with model and simulation
        packet._register_with_sim(self.sim)
        packet._register_with_model(self.model)
        self.model._add_packet(packet)

        # packet generation event
        event_generation = Event(
            timestamp=timestamp,
            etype=EventType.PACKET_GENERATION,
            module_id=id(self),
            packet_id=id(packet)
        )

        # Choose a destination module for the packet
        destination = choose_output(self.outputs, packet.ptype)

        if destination is None:
            # This should never happen
            logger.error("%8.3f -- %s at node %s, packet id: %s - Destination not found!" %
                         (self.get_time(), event_generation.etype, self.name, str(id(packet))))
            raise TypeError("Destination not found in outputs of node %s. Make sure there's a Queue as output." %
                            self.name)

        # packet arrival event (at the module connected as output to the source)
        event_arrival = Event(
            timestamp=timestamp,
            etype=EventType.QUEUE_PACKET_ARRIVAL,
            module_id=id(destination),
            packet_id=id(packet)
        )

        self.sim._add_event(event_generation)
        self.sim._add_event(event_arrival)


class PermitSource:
    """
    A generator for Permit packets
    """

    def __init__(self, rate, outputs=None, distribution='Poisson', sim=None, model=None, name=None):
        """
        Constructor

        :param rate: A float for packet generation rate
        :param outputs: A list of dictionaries {'module': ..., 'prob': ...}
        :param distribution: A string. Currently only 'Poisson' is supported
        """

        self.rate = rate
        self.outputs = outputs
        self.distribution = distribution
        self.sim = sim
        self.model = model
        self.name = name
        self.results = Results()

    def _register_with_model(self, model):
        self.model = model

    def _register_with_sim(self, sim):
        self.sim = sim

    def generate_packet(self):
        """
        Generate a single packet in a time-slot coming from some distribution.
        :return: /
        """

        # Todo: some of the events stuff below might need to be moved to simulation.process_event

        # Timestamp of next packet generation
        noise = (np.random.rand() - 0.5) / 20  # added noise
        timestamp = self.sim._get_time() + np.random.poisson(1 / self.rate, 1)[0] + noise

        # Create packet
        packet = Packet(
            ptype=PacketType.PERMIT,
            active=True,
            module_id=id(self),
            generation_time=timestamp
        )

        # Register packet with model and simulation
        packet._register_with_sim(self.sim)
        packet._register_with_model(self.model)
        self.model._add_packet(packet)

        # packet generation event
        event_generation = Event(
            timestamp=timestamp,
            etype=EventType.PERMIT_GENERATION,
            module_id=id(self),
            packet_id=id(packet)
        )

        # Choose a destination module for the packet
        destination = choose_output(self.outputs, packet.ptype)

        if destination is None:
            # This should never happen
            logger.error("%8.3f -- %s at node %s, packet id: %s - Destination not found!" %
                         (self.get_time(), event_generation.etype, self.name, str(id(packet))))
            raise TypeError("Destination not found in outputs of node %s. Make sure there's a Queue as output." %
                            self.name)

        # packet arrival event (at the module connected as output to the source)
        # todo: Move event generations in gsim_utils.create_event
        event_arrival = Event(
            timestamp=timestamp,
            etype=EventType.QUEUE_PACKET_ARRIVAL,
            module_id=id(destination),
            packet_id=id(packet)
        )

        self.sim._add_event(event_generation)
        self.sim._add_event(event_arrival)


class NegativeSource:
    """
    A generator for Negative Signals. This module needs to receive a single packet (of any type) as input, in order
    to generate a single Negative Signal.
    """

    def __init__(self, outputs=None, outputs_signal=None, sim=None, model=None, name=None):
        """
        Constructor

        :param rate: A float for packet generation rate
        :param outputs: A list of dictionaries {'module': ..., 'prob': ...}
        :param distribution: A string. Currently only 'Poisson' is supported
        """

        self.outputs = outputs  # Outputs for forwarding data packets
        self.outputs_signal = outputs_signal  # Outputs for negative signals
        self.sim = sim
        self.model = model
        self.name = name
        self.results = Results()

    def _register_with_model(self, model):
        self.model = model

    def _register_with_sim(self, sim):
        self.sim = sim

    def generate_signal(self):
        """
        Generate a negative signal now.
        :return: /
        """

        # Create packet
        packet = Packet(
            ptype=PacketType.NEG_SIGNAL,
            active=True,
            module_id=id(self),
            generation_time=self.sim._get_time(),
            pkts_to_remove=1,
        )

        # Register packet with model and simulation
        packet._register_with_sim(self.sim)
        packet._register_with_model(self.model)
        self.model._add_packet(packet)

        # Create packet arrival event (at the module connected as output to the source)
        destination = choose_output(self.outputs_signal, packet.ptype)
        event = create_arrival_event(destination, self.sim._get_time(), id(packet), pkt_type=packet.ptype)
        self.sim._add_event(event)


