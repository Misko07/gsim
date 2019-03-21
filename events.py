
class Event:

    def __init__(self, timestamp=None, etype=None, module_id=None, packet_id=None):
        self.__timestamp = timestamp
        self.etype = etype
        self.module_id = module_id
        self.packet_id = packet_id

    def __eq__(self, other):
        return self.get_timestamp() == other.get_timestamp()

    def __lt__(self, other):
        return self.get_timestamp() < other.get_timestamp()

    def __gt__(self, other):
        return self.get_timestamp() > other.get_timestamp()

    def get_module_id(self):
        return self.module_id

    def get_packet_id(self):
        return self.packet_id

    def get_timestamp(self):
        return self.__timestamp

