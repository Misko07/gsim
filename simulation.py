"""
This file contains the classes for `simulation` and `model`.
A `simulation` object runs the engine of the simulator, looping through events.
A `model` object is needed to keep track of all modules and packets in the simulation.
"""

from gsim.modules import Queue, Server, AnomalyDetector, PermitConnector
from gsim.events import Event, EventType
from gsim.packets import PacketType
from gsim.generators import Source, PermitSource, NegativeSource
from gsim.configs import ROOT_DIR
import gsim.gsim_utils as gu

from queue import PriorityQueue
from datetime import datetime
import logging.config
import pandas as pd
import numpy as np
import logging
import os

logging.config.fileConfig('logging.conf')
logger = logging.getLogger('simulation')


class Simulation:

    def __init__(self, duration, model=None):
        self.duration = duration
        self.model = model
        self.pq = PriorityQueue()
        self.time = 0

    def process_event(self, event):

        # Each event has a module and packet associated with it
        module_id = event.get_module_id()
        packet_id = event.get_packet_id()
        module_ = self.model.get_module(module_id)
        packet = self.model.get_packet(packet_id)

        if module_ is None:
            raise ValueError("Module with id %s not found! Check if all modules are registered with model using "
                             "`model.add_module()`." % module_id)

        if event.etype == EventType.SERVICE_COMPLETE:

            logger.info("%8.3f -- %s at node %s, packet id: %s" %
                        (self.get_time(), event.etype, module_.name, str(packet_id)))
            del event
            module_.busy = False

            # Send to one of the module's outputs - at least one of the outputs must be a Queue!!
            destination = gu.choose_output(module_.outputs, packet.ptype)
            if destination is None:
                # This should never happen
                logger.error("%8.3f -- node %s, packet id: %s - Destination not found!" %
                             (self.get_time(), module_.name, str(packet_id)))
                raise TypeError("Destination not found in outputs of node %s. Make sure there's a Queue as output." %
                                module_.name)

            # Put new event in priority queue
            event = gu.create_arrival_event(destination, self.get_time(), packet_id, packet.ptype)
            self.add_event(event)

            # Get a new packet from inputs
            input_module = module_.inputs[0]['module']
            # todo: Implement multiple inputs to a server

            if type(input_module) == Queue:
                logger.debug("%8.3f -- Server %s asks input %s (len: %d) for more packets" %
                             (self.get_time(), module_.name, input_module.name, len(input_module)))

            if type(input_module) == Queue and len(input_module) > 0:
                new_packet = input_module.pop()
                event = gu.create_arrival_event(module_, self.get_time(), id(new_packet), packet.ptype)
                self.add_event(event)

        elif event.etype == EventType.DETECTOR_SERVICE_COMPLETE:

            # Make a decision on malicious packet detection
            if packet.is_malicious():
                detect_prob = module_.tp_rate
            elif packet.is_normal():
                detect_prob = module_.fp_rate
            else:
                detect_prob = 0
                logger.warning("Invalid packet type received in Anomaly detector. Treated as normal.")
                # raise ValueError("Invalid packet type!")

            decision_attack = np.random.choice([True, False], 1, p=[detect_prob, 1-detect_prob])[0]
            packet.detected = decision_attack

            logger.info("%8.3f -- %s at node %s, packet id: %s, detected attack: %s" %
                        (self.get_time(), event.etype, module_.name, str(packet_id), str(decision_attack)))

            del event
            module_.busy = False

            if decision_attack:
                destination = gu.choose_output(module_.outputs_detected, packet.ptype)
            else:
                destination = gu.choose_output(module_.outputs, packet.ptype)
            if destination is None:
                # This should never happen
                logger.error("%8.3f -- node %s, packet id: %s - Destination not found!" %
                             (self.get_time(), module_.name, str(packet_id)))
                raise TypeError("Destination not found in outputs of node %s. Make sure there's a Queue as output." %
                                module_.name)

            event = gu.create_arrival_event(destination, self.get_time(), packet_id, packet.ptype)
            self.add_event(event)

            # Get a new packet from inputs (if queue)
            input_module = module_.inputs[0]['module']
            # todo: Implement multiple inputs to a server
            if type(input_module) == Queue:
                logger.debug("%8.3f -- AnomalyDetector %s asks input %s (len: %d) for more packets" %
                             (self.get_time(), module_.name, input_module.name, len(input_module)))

                if len(input_module) > 0:
                    new_packet = input_module.pop()
                    event = gu.create_arrival_event(module_, self.get_time(), id(new_packet), packet.ptype)
                    self.add_event(event)

        elif event.etype == EventType.PACKET_GENERATION or event.etype == EventType.PERMIT_GENERATION:
            # generate a new packet
            logger.info("%8.3f -- %s at node %s, packet id: %s" %
                        (self.get_time(), event.etype, module_.name, str(packet_id)))
            module_.generate_packet()
            del event

        elif event.etype == EventType.QUEUE_PACKET_ARRIVAL:
            # A packet has arrived in a queue
            packet.set_module(module_id)

            if packet.ptype == PacketType.PERMIT and module_.name != 'qp':
                print('error, module_.name: %s, packet_id: %s' % (module_.name, packet_id))

            # If packet is Data packet (NORMAL, MALICIOUS), or PERMIT
            if packet.ptype != PacketType.NEG_SIGNAL:
                module_.appendleft(packet)
                logger.info("%8.3f -- %s at node %s (qlen: %d), packet id: %s, type: %s" %
                            (self.get_time(), event.etype, module_.name, len(module_), str(packet_id), packet.ptype))
                del event

                # if packet is first in the queue, inform the output module of this
                if len(module_) == 1:
                    destination = gu.choose_output(module_.outputs, packet.ptype)
                    if destination:
                        # Forward packet to destination if not busy, otherwise do nothing
                        event = gu.create_arrival_event(destination, self.get_time(), packet_id, packet.ptype)
                        self.add_event(event)
                        module_.pop()

            # If by mistake packet is NEG_SIGNAL
            else:
                raise ValueError("Negative packet received as QUEUE_PACKET_ARRIVAL event!")

        elif event.etype == EventType.QUEUE_NEG_PACKET_ARRIVAL:
            # A negative signal has arrived in a queue
            packet.set_module(module_id)

            # Check if packet is not negative, or module is not queue
            if packet.ptype != PacketType.NEG_SIGNAL:
                logger.error("%8.3f -- %s - wrong packet type at node %s (qlen: %d), packet id: %s, type: %s" %
                             (self.get_time(), event.etype, module_.name, len(module_), str(packet_id), packet.ptype))
                raise ValueError("Expected NEG_SIGNAL, but received different packet type as QUEUE_NEG_PACKET_ARRIVAL.")

            if type(module_) != Queue:
                logger.error("%8.3f -- %s - negative signal received at non-queue module %s (qlen: %d), packet id: %s, "
                             "type: %s" % (self.get_time(), event.etype, module_.name, len(module_), str(packet_id),
                                           packet.ptype))
                raise ValueError("NEG_SIGNAL arrived in non-queue module in QUEUE_NEG_PACKET_ARRIVAL.")

            # Remove packet.pkts_to_remove pakets from back of queue
            num_removed = packet.remove_data_packet(module_)

            logger.info("%8.3f -- %s at node %s (qlen: %d), packet id: %s, type: %s" %
                        (self.get_time(), event.etype, module_.name, len(module_), str(packet_id), packet.ptype))
            logger.info("%8.3f -- %s at node %s: %d packets removed (qlen: %d -> %d)" %
                        (self.get_time(), event.etype, module_.name, num_removed, len(module_) + num_removed,
                         len(module_)))
            del event

        elif event.etype == EventType.SERVER_PACKET_ARRIVAL or event.etype == EventType.DETECTOR_PACKET_ARRIVAL:
            # A packet has arrived in a server or anomaly detector
            # Todo: What if neg-signal or permit packet arrive here?  -- they should just be treated as normal packets
            packet.set_module(module_id)
            if not module_.busy:
                module_.busy = True

            # Schedule service end time
            service_duration = np.random.exponential(1 / module_.service_rate)

            logger.info("%8.3f -- %s at node %s, packet id: %s, service duration: %.3f" %
                        (self.get_time(), event.etype, module_.name, str(packet_id), service_duration))

            timestamp = service_duration + self.get_time()
            etype = EventType.SERVICE_COMPLETE
            if event.etype == EventType.DETECTOR_PACKET_ARRIVAL:
                etype = EventType.DETECTOR_SERVICE_COMPLETE
            del event

            event = Event(
                timestamp=timestamp,
                etype=etype,
                module_id=module_id,
                packet_id=packet_id
            )
            self.add_event(event)

        elif event.etype == EventType.NEG_PACKET_GENERATION:
            # A negative signal needs to be generated at a NegativeSource
            packet.set_module(module_id)  # Set current (data) packet to module NegSource - this is its final dest.
            module_.generate_signal()

        elif event.etype == EventType.CONNECTOR_PERMIT_ARRIVAL:
            # A permit has arrived at a PermitConnector
            packet.set_module(module_id)

            logger.info("%8.3f -- %s at node %s (has_packet: %s, has_permit: %s), packet id: %s, type: %s" %
                        (self.get_time(), event.etype, module_.name, module_.has_packet(), module_.has_permit(),
                         str(packet_id), packet.ptype))

            if module_.has_packet():
                # Forward packet to output
                destination = gu.choose_output(module_.outputs, packet.ptype)
                packet_id = id(module_.packet)
                event = gu.create_arrival_event(destination, self.get_time(), packet_id, packet.ptype)
                self.add_event(event)
                module_.packet = None
                module_.permit = None
                logger.debug("%8.3f -- %s forwards packet_id: %d. has_packet: %s, has_permit: %s" %
                             (self.get_time(), module_.name, packet_id, module_.has_packet(), module_.has_permit()))

                # Get a new packet from packets input (if queue)
                input_pkt_module = module_.inputs_pkt[0]['module']
                if type(input_pkt_module) == Queue:
                    logger.debug("%8.3f -- PermitConnector %s asks packet input %s (len: %d) for more packets" %
                                 (self.get_time(), module_.name, input_pkt_module.name, len(input_pkt_module)))

                    if len(input_pkt_module) > 0:
                        new_packet = input_pkt_module.pop()
                        event = gu.create_arrival_event(module_, self.get_time(), id(new_packet), new_packet.ptype)
                        self.add_event(event)
                else:
                    raise ValueError("Invalid network architecture!")

                # Get a new permit from permits input (if queue)
                input_prm_module = module_.inputs_prm[0]['module']
                if type(input_prm_module) == Queue:
                    logger.debug("%8.3f -- PermitConnector %s asks permit input %s (len: %d) for more permits" %
                                 (self.get_time(), module_.name, input_prm_module.name, len(input_prm_module)))

                    if len(input_prm_module) > 0:
                        new_packet = input_prm_module.pop()
                        event = gu.create_arrival_event(module_, self.get_time(), id(new_packet), new_packet.ptype)
                        self.add_event(event)
                else:
                    raise ValueError("Invalid network architecture!")

            else:
                module_.permit = packet

        elif event.etype == EventType.CONNECTOR_PACKET_ARRIVAL:
            # A data packet has arrived at a PermitConnector
            packet.set_module(module_id)

            logger.info("%8.3f -- %s at node %s (has_packet: %s, has_permit: %s), packet id: %s, type: %s" %
                        (self.get_time(), event.etype, module_.name, module_.has_packet(), module_.has_permit(),
                         str(packet_id), packet.ptype))

            if module_.has_permit():
                # Forward packet to output
                destination = gu.choose_output(module_.outputs, packet.ptype)
                event = gu.create_arrival_event(destination, self.get_time(), packet_id, packet.ptype)
                self.add_event(event)
                module_.packet = None
                module_.permit = None
                logger.debug("%8.3f -- %s forwards packet_id: %d. has_packet: %s, has_permit: %s" %
                             (self.get_time(), module_.name, packet_id, module_.has_packet(), module_.has_permit()))

                # Get a new packet from packets input (if queue)
                input_pkt_module = module_.inputs_pkt[0]['module']
                if type(input_pkt_module) == Queue:
                    logger.debug("%8.3f -- PermitConnector %s asks packet input %s (len: %d) for more packets" %
                                 (self.get_time(), module_.name, input_pkt_module.name, len(input_pkt_module)))

                    if len(input_pkt_module) > 0:
                        new_packet = input_pkt_module.pop()
                        event = gu.create_arrival_event(module_, self.get_time(), id(new_packet), new_packet.ptype)
                        self.add_event(event)
                else:
                    raise ValueError("Invalid network architecture!")

                # Get a new permit from permits input (if queue)
                input_prm_module = module_.inputs_prm[0]['module']
                if type(input_prm_module) == Queue:
                    logger.debug("%8.3f -- PermitConnector %s asks permit input %s (len: %d) for more permits" %
                                 (self.get_time(), module_.name, input_prm_module.name, len(input_prm_module)))

                    if len(input_prm_module) > 0:
                        new_packet = input_prm_module.pop()
                        event = gu.create_arrival_event(module_, self.get_time(), id(new_packet), new_packet.ptype)
                        self.add_event(event)
                else:
                    raise ValueError("Invalid network architecture!")

            else:
                module_.packet = packet

    def get_summary(self):

        vector_res = {
            'module_name': [],
            'module_class': [],
            'module_id': [],
            'packet_id': [],
            'arrival_time': [],
            'departure_time': [],
            'removal_time': [],
            'malicious': [],
            'neg_signal': [],
            'permit': []
        }

        scalar_res = {
            'module_name': [],
            'module_class': [],
            'module_id': [],
            'total_arrivals': [],
            'total_departures': [],
            'normal_arrivals': [],
            'normal_departures': [],
            'attack_arrivals': [],
            'attack_departures': [],
            'permit_arrivals': [],
            'permit_departures': [],
            'neg_signal_arrivals': [],
            'neg_signal_departures': [],
            'normal_removals': [],
            'attack_removals': [],
            'permit_removals': [],
            'mean_waittime_normal': [],
            'mean_waittime_permit': []
        }

        for module in self.model.get_modules():
            if hasattr(module, 'results'):

                # Get vector results
                module_vector_res = module.results.get_vector_results()
                assert(len(module_vector_res.keys()) == 7)

                vector_res['packet_id'].extend(module_vector_res['packet_id'])
                vector_res['arrival_time'].extend(module_vector_res['arrival_time'])
                vector_res['departure_time'].extend(module_vector_res['departure_time'])
                vector_res['removal_time'].extend(module_vector_res['removal_time'])
                vector_res['malicious'].extend(module_vector_res['malicious'])
                vector_res['permit'].extend(module_vector_res['permit'])
                vector_res['neg_signal'].extend(module_vector_res['negative'])
                vector_res['module_class'].extend([module.__class__] * len(module_vector_res.get('packet_id')))
                vector_res['module_name'].extend([module.name] * len(module_vector_res.get('packet_id')))
                vector_res['module_id'].extend([id(module)] * len(module_vector_res.get('packet_id')))

                # Get scalar results
                module_scalar_res = module.results.get_scalar_results()
                assert(len(module_scalar_res) == 15)

                scalar_res['module_name'].append(module.name)
                scalar_res['module_id'].append(id(module))
                scalar_res['module_class'].append(module.__class__)
                scalar_res['total_arrivals'].append(module_scalar_res[0])
                scalar_res['total_departures'].append(module_scalar_res[1])
                scalar_res['normal_arrivals'].append(module_scalar_res[2])
                scalar_res['normal_departures'].append(module_scalar_res[3])
                scalar_res['attack_arrivals'].append(module_scalar_res[4])
                scalar_res['attack_departures'].append(module_scalar_res[5])
                scalar_res['permit_arrivals'].append(module_scalar_res[6])
                scalar_res['permit_departures'].append(module_scalar_res[7])
                scalar_res['neg_signal_arrivals'].append(module_scalar_res[8])
                scalar_res['neg_signal_departures'].append(module_scalar_res[9])
                scalar_res['normal_removals'].append(module_scalar_res[10])
                scalar_res['attack_removals'].append(module_scalar_res[11])
                scalar_res['permit_removals'].append(module_scalar_res[12])
                scalar_res['mean_waittime_normal'].append(module_scalar_res[13])
                scalar_res['mean_waittime_permit'].append(module_scalar_res[14])

        # Create Dataframes for results
        df_vector = pd.DataFrame(vector_res, columns=list(vector_res.keys()))
        df_scalar = pd.DataFrame(scalar_res, columns=list(scalar_res.keys()))

        # Save results to csv
        results_path = os.path.join(ROOT_DIR, 'results')
        if not os.path.isdir(results_path):
            os.mkdir(results_path)
        datenum = datetime.now().strftime("%y%m%d-%H%M%S")
        df_vector.to_csv(os.path.join(results_path, 'vec-%s.csv' % datenum))
        df_scalar.to_csv(os.path.join(results_path, 'sca-%s.csv' % datenum))
        logger.info("Simulation results (scalars and vectors) saved in %s." % results_path)

    def add_model(self, model):
        self.model = model
        for module in model.get_modules():
            module.register_with_sim(self)
        for source in model.get_sources():
            source.register_with_sim(self)

    def get_model(self):
        return self.model

    def get_time(self):
        return self.time

    def add_event(self, event):
        self.pq.put(event)

    def get_duration(self):
        return self.duration

    def run(self):

        print("Simulation running..")

        # Start data generators
        model = self.model
        for _, source in model.sources.items():
            source.generate_packet()

        while self.pq.qsize() > 0:

            # Get next event from queue
            event = self.pq.get()
            self.time = event.get_timestamp()

            # Check if simulation end reached
            if self.time > self.duration:
                break

            # Process event
            self.process_event(event)

        # End of simulationerror
        self.get_summary()


class Model:

    def __init__(self, name=None):
        self.modules = {}
        self.packets = {}  # todo: check if I really need this
        self.sources = {}
        self.destinations = {}
        self.name = name

    def add_module(self, module):
        module.register_with_model(self)
        self.modules[id(module)] = module

        if type(module) == Source or type(module) == PermitSource:
            self.sources[id(module)] = module

    def get_module(self, module_id):
        return self.modules.get(module_id)

    def get_modules(self):
        return list(self.modules.values())

    def get_sources(self):
        return list(self.sources.values())

    def add_packet(self, packet):
        self.packets[id(packet)] = packet

    def get_packet(self, packet_id):
        return self.packets.get(packet_id, None)


if __name__ == '__main__':

    sim = Simulation(duration=2000)

    # Declare model's components
    q1 = Queue(name='q1')
    qp = Queue(name='qp')
    qs = Queue(name='qs')
    s1 = Server(name='s1', service_rate=0.3)
    q2 = Queue(name='q2')
    ad = AnomalyDetector(name='detector1', service_rate=0.2, tp_rate=0.9, fp_rate=0.05)
    q_nor = Queue(name='dest_normal')
    q_att = Queue(name='dest_attack')
    conn = PermitConnector(name='connector')
    gen = Source(rate=0.3, attack_prob=0.2, name='gen')
    gen_permit = PermitSource(rate=0.3, name='permit_gen')
    gen_neg = NegativeSource(name='gen_neg')

    # Add component's inputs and outputs
    gen.outputs = [{'module': q1, 'prob': 1}]
    gen_permit.outputs = [{'module': qp, 'prob': 1}]
    q1.outputs = [{'module': conn, 'prob': 1}]
    qp.outputs = [{'module': conn, 'prob': 1}]
    conn.inputs_pkt = [{'module': q1, 'prob': 1}]
    conn.inputs_prm = [{'module': qp, 'prob': 1}]
    conn.outputs = [{'module': qs, 'prob': 1}]
    qs.outputs = [{'module': s1, 'prob': 1}]
    s1.inputs = [{'module': qs, 'prob': 1}]
    s1.outputs = [{'module': q2, 'prob': 1}]
    q2.outputs = [{'module': ad, 'prob': 1}]
    ad.inputs = [{'module': q2, 'prob': 1}]
    ad.outputs = [{'module': q_nor, 'prob': 1}]
    ad.outputs_detected = [{'module': gen_neg, 'prob': 1}]
    gen_neg.outputs = [{'module': qp, 'prob': 1}]

    # Register components to model
    m = Model()
    m.add_module(gen)
    m.add_module(gen_permit)
    m.add_module(q1)
    m.add_module(qp)
    m.add_module(qs)
    m.add_module(conn)
    m.add_module(s1)
    m.add_module(q2)
    m.add_module(ad)
    m.add_module(q_nor)
    m.add_module(q_att)
    m.add_module(gen_neg)

    # Register model with simulation.
    # This also registers all model's modules with simulation.
    sim.add_model(m)
    sim.run()
