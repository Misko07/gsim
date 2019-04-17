import numpy as np
from events import Event
from modules import Packet
import gsim_utils as gu
import logging
from results import Results


logging.config.fileConfig("logging.conf")
logger = logging.getLogger('generators')


class Source:
    """
    A source generates Packets
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
        self.num_generated = 0
        self.results = Results()

    def register_with_model(self, model):
        self.model = model

    def register_with_sim(self, sim):
        self.sim = sim

    def generate_packet(self):
        """
        Generate a single packet in a time-slot coming from some distribution.
        :return: /
        """

        # Timestamp of next packet generation
        timestamp = self.sim.get_time() + np.random.poisson(self.rate, 1)[0]

        # Create packet
        packet = Packet(
            size=None,
            malicious=np.random.choice([True, False], 1, p=[self.attack_prob, 1-self.attack_prob])[0],
            active=True,
            module_id=id(self),
            generation_time=timestamp
        )

        # Register packet with model and simulation
        packet.register_with_sim(self.sim)
        packet.register_with_model(self.model)
        self.model.add_packet(packet)

        # packet generation event
        event1 = Event(
            timestamp=timestamp,
            etype='PACKET_GENERATION',
            module_id=id(self),
            packet_id=id(packet)
        )

        # Choose a destination module for the packet
        destination = gu.choose_output(self.outputs)

        if destination is None:
            # This should never happen
            logger.error("%8.3f -- %s at node %s, packet id: %s - Destination not found!" %
                         (self.get_time(), event1.etype, self.name, str(id(packet))))
            raise TypeError("Destination not found in outputs of node %s. Make sure there's a Queue as output." %
                            self.name)

        # packet arrival event (at the module connected as output to the source)
        event2 = Event(
            timestamp=timestamp,
            etype='QUEUE_PACKET_ARRIVAL',
            module_id=id(destination),
            packet_id=id(packet)
        )

        self.sim.add_event(event2)
        self.sim.add_event(event1)
        self.num_generated += 1

