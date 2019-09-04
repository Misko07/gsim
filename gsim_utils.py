from gsim.modules import Server, Queue, AnomalyDetector
from gsim.events import Event, EventType
import numpy as np
import logging


logging.config.fileConfig("logging.conf")
logger = logging.getLogger('utils')


def choose_output(outputs):
    """
    Choose a destination module for a packet, out of a list of output modules - according to a probability distribution
    for each of them, and if they're not busy

    :param outputs:
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

    index = np.random.choice(len(outputs_subset), probs_subset_adjusted)[0]
    return outputs_subset[index]


def create_event(destination, time_now, packet_id):

    # Todo check if I'm not missing some cases
    etype = None
    if type(destination) == Server and not destination.busy:
        etype = EventType.SERVER_PACKET_ARRIVAL
    elif type(destination) == Queue:
        etype = EventType.QUEUE_PACKET_ARRIVAL
    elif type(destination) == AnomalyDetector and not destination.busy:
        etype = EventType.DETECTOR_PACKET_ARRIVAL

    event = Event(
        timestamp=time_now,
        etype=etype,
        module_id=id(destination),
        packet_id=packet_id
    )

    logger.debug("%8.3f -- Created event %s for node_id: %s, packet_id: %s" %
                 (time_now, event.etype, destination.name, str(packet_id)))

    return event
