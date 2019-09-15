from gsim.modules import Server, Queue, AnomalyDetector, PermitConnector
from gsim.events import Event, EventType
from gsim.packets import PacketType
from gsim.configs import ROOT_DIR
import numpy as np
import logging


logging.config.fileConfig(ROOT_DIR + "/logging.conf")
logger = logging.getLogger('utils')


def choose_output(outputs, pkt_type=None):
    """
    Choose a destination module for a packet, out of a list of output modules - according to a probability distribution
    for each of them, and if they're not busy

    :param outputs:
    :param pkt_type:
    :return:
    """

    if outputs is None:
        return None

    # Check if outputs is iterable
    try:
        iter(outputs)
    except TypeError as e:
        raise TypeError("Module outputs must be iterable.")

    output_modules = [o['module'] for o in outputs]
    output_probs = [o['prob'] for o in outputs]

    # Discard outputs which are busy
    outputs_subset = []
    probs_subset = []
    for module, prob in zip(output_modules, output_probs):
        if hasattr(module, 'busy') and module.busy == True:
            continue

        # Special conditions if next module is Permit Connector
        if type(module) == PermitConnector:
            if pkt_type == PacketType.PERMIT and module.has_permit():
                continue
            if pkt_type in [PacketType.NORMAL, PacketType.MALICIOUS] and module.has_packet():
                continue

        outputs_subset.append(module)
        probs_subset.append(prob)

    # If there's no available output, return none
    if len(outputs_subset) == 0:
        return None

    # If some outputs are busy at the moment, probability of forwarding packet to the rest should be updated
    probs_sum = np.sum(probs_subset)
    if probs_sum < 1:
        # adjust probabilities
        probs_subset_adjusted = []
        for prob in probs_subset:
            probs_subset_adjusted.append(prob * (2 - probs_sum))
    else:
        probs_subset_adjusted = probs_subset

    assert(np.sum(probs_subset_adjusted) == 1)

    # Pick one output and return it
    index = np.random.choice(len(outputs_subset), p=probs_subset_adjusted)
    return outputs_subset[index]


def create_arrival_event(destination, time_now, packet_id, pkt_type=None):

    # Todo check if I'm not missing something
    etype = None
    if "NegativeSource" in str(type(destination)):  # Todo: remove this workaround
        etype = EventType.NEG_PACKET_GENERATION
    elif type(destination) == Queue and pkt_type == PacketType.NEG_SIGNAL:
        etype = EventType.QUEUE_NEG_PACKET_ARRIVAL
    elif type(destination) == Server and not destination.busy:
        etype = EventType.SERVER_PACKET_ARRIVAL
    elif type(destination) == Queue:
        etype = EventType.QUEUE_PACKET_ARRIVAL
    elif type(destination) == AnomalyDetector and not destination.busy:
        etype = EventType.DETECTOR_PACKET_ARRIVAL
    elif type(destination) == PermitConnector and pkt_type == PacketType.PERMIT and not destination.has_permit():
        etype = EventType.CONNECTOR_PERMIT_ARRIVAL
    elif type(destination) == PermitConnector and (pkt_type == PacketType.NORMAL or pkt_type == PacketType.MALICIOUS) \
            and not destination.has_packet():
        etype = EventType.CONNECTOR_PACKET_ARRIVAL

    if etype:
        event = Event(
            timestamp=time_now,
            etype=etype,
            module_id=id(destination),
            packet_id=packet_id
        )
        logger.debug("%8.3f -- Created event %s for node_id: %s, packet_id: %s" %
                     (time_now, event.etype, destination.name, str(packet_id)))
    else:
        event = None
        logger.error("%8.3f -- Event not created for destination: %s, packet_id: %s" %
                     (time_now, destination.name, str(packet_id)))

    return event
