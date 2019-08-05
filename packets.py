from enum import Enum


class PacketType(Enum):
    NORMAL = 0
    MALICIOUS = 1
    PERMIT = 2
    NEG_SIGNAL = 3


class Packet:

    def __init__(self, model=None, sim=None, pkt_type=None, detected=None, active=True, module_id=None,
                 generation_time=None, pkts_to_remove=None):
        self.sim = sim
        self.model = model
        self.type = pkt_type
        self.pkts_to_remove = pkts_to_remove  # num packets to remove from queue (if of type NEG_SIGNAL)
        self.detected = detected  # If an anomaly detector has marked it as malicious
        self.active = active  # inactive when reaches destination
        self.module_id = module_id  # the current module it's in
        self.generation_time = generation_time

    def is_normal(self):
        return self.type == PacketType.NORMAL

    def is_malicious(self):
        return self.type == PacketType.MALICIOUS

    def is_neg_signal(self):
        return self.type == PacketType.NEG_SIGNAL

    def set_module(self, module_id):
        """ Change self.module_id when sent from one (old) module to another (new)

        :return: /
        """

        # Todo: Update results for NEG_SIGNAL and PERMIT type of Packets

        old_module_id = self.module_id
        old_module = self.model.get_module(old_module_id)
        if hasattr(old_module, 'results'):
            old_module.results.add_packet_departure(id(self), self.sim.get_time(), self.is_malicious())
        new_module = self.model.get_module(module_id)
        if hasattr(new_module, 'results'):
            new_module.results.add_packet_arrival(id(self), self.sim.get_time(), self.is_malicious())
        self.module_id = module_id

    def register_with_model(self, model):
        self.model = model

    def register_with_sim(self, sim):
        self.sim = sim