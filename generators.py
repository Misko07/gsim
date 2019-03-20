import numpy as np
from events import Event
from modules import Packet


class Source:
    """
    A source generates Packets
    """

    def __init__(self, rate, outputs, distribution='Poisson', attack_prob=0, sim=None):
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
        self.attack_prob = attack_prob

    def generate_packet(self):
        """
        Generate a single packet in a time-slot coming from some distribution.
        :return: /
        """

        # Timestamp of next packet generation
        if self.distribution == 'Poisson':
            timestamp = self.sim.get_time() + np.random.poisson(self.rate, 1)

        # Don't generate a packet if simulation duration reached
        if timestamp > self.sim.get_duration():
            return

        # Choose a destination module for the packet
        output_modules = [o['module'] for o in self.outputs]
        output_probs = [o['prob'] for o in self.outputs]
        print('output_modules', output_modules)
        index = np.random.choice(len(output_modules), output_probs)
        dest_module = output_modules[index]

        # Create packet
        packet = Packet(
            size=None,
            malicious=np.random.choice([True, False], 1, p=[self.attack_prob, 1-self.attack_prob]),
            active=True,
            module_id=id(dest_module),
            generation_time=timestamp
        )

        # packet generation event
        event = Event(
            timestamp=timestamp,
            etype='PACKET_GENERATION',
            module_id=id(self),
            packet_id=id(packet)
        )

        # packet arrival event (at the module connected as output to the source)
        event = Event(
            timestamp=timestamp,
            etype='PACKET_ARRIVAL',
            module_id=id(dest_module),
            packet_id=id(packet)
        )

        model = self.sim.get_model()
        model.add_packet(packet)
        self.sim.add_event(event)

