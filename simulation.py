from queue import PriorityQueue
import gsim_utils as gu
from modules import Queue, Server
from generators import Source
from datetime import datetime
from events import Event
import logging.config
import pandas as pd
import numpy as np
import logging
import os


# if os.path.isfile('logs.log'):
#     os.unlink('logs.log')

logging.config.fileConfig('logging.conf')
logger = logging.getLogger('simulation')


class Simulation:

    def __init__(self, duration, model=None):
        self.duration = duration
        self.model = model
        self.pq = PriorityQueue()
        self.time = 0

    def get_summary(self, add_to_log=True):

        if add_to_log:
            logger.info("*** Summary for model %s ***" % self.model.name)
            logger.info("- " * 30)

        results = {
            'module_name': [],
            'module_class': [],
            'module_id': [],
            'packet_id': [],
            'arrival_time': [],
            'departure_time': []
        }

        for module in self.model.get_modules():
            if add_to_log:
                logger.info('Module: %s' % module.name)
                logger.info('-' * 30)

            if hasattr(module, 'results'):
                module_results = module.results.get_summary(add_to_log=add_to_log)
                results['packet_id'].extend(module_results['packet_id'])
                results['arrival_time'].extend(module_results['arrival_time'])
                results['departure_time'].extend(module_results['departure_time'])
                results['module_class'].extend([module.__class__] * len(module_results.get('packet_id')))
                results['module_name'].extend([module.name] * len(module_results.get('packet_id')))
                results['module_id'].extend([id(module)] * len(module_results.get('packet_id')))

            if add_to_log:
                logger.info("- " * 30)

        df = pd.DataFrame(results, columns=list(results.keys()))
        datenum = datetime.now().strftime("%y%m%d-%H%M%S")
        df.to_csv('results_%s.csv' % datenum)

    def process_event(self, event):
        # Each event has a module and packet associated with it

        if event.etype == 'SERVICE_COMPLETE':
            server_id = event.get_module_id()
            packet_id = event.get_packet_id()
            server = self.model.get_module(server_id)
            packet = self.model.get_packet(packet_id)
            logger.info("%8.3f -- %s at node %s, packet id: %s" %
                         (self.get_time(), event.etype, server.name, str(packet_id)))
            del event
            server.busy = False

            # Send to one of the module's outputs
            destination = gu.choose_output(server.outputs)
            if type(destination) == Server and not destination.busy:
                # move packet to server
                event = Event(
                    timestamp=self.get_time(),
                    etype='SERVER_PACKET_ARRIVAL',
                    module_id=id(destination),
                    packet_id=packet_id
                )
                self.add_event(event)
            elif type(destination) == Queue:
                # Schedule a queue packet arrival event
                event = Event(
                    timestamp=self.get_time(),
                    etype='QUEUE_PACKET_ARRIVAL',
                    module_id=id(destination),
                    packet_id=id(packet)
                )
                self.add_event(event)

            # Get a new packet from inputs
            # todo: Implement multiple inputs to a server
            input_module = server.inputs[0]['module']

            logger.debug("%8.3f -- Server %s asks input %s (len: %d) for more packets" %
                          (self.get_time(), server.name, input_module.name, len(input_module)))
            if type(input_module) == Queue and len(input_module) > 0:
                new_packet = input_module.pop()
                event = Event(
                    timestamp=self.get_time(),
                    etype='SERVER_PACKET_ARRIVAL',
                    module_id=server_id,
                    packet_id=id(new_packet)
                )
                self.add_event(event)

        elif event.etype == 'PACKET_GENERATION':
            # generate a new packet
            source_id = event.get_module_id()
            packet_id = event.get_packet_id()
            source = self.model.get_module(source_id)
            logger.info("%8.3f -- %s at node %s, packet id: %s" %
                         (self.get_time(), event.etype, source.name, str(packet_id)))
            source.generate_packet()
            del event

        elif event.etype == 'QUEUE_PACKET_ARRIVAL':
            # A packet has arrived in a queue
            queue_id = event.get_module_id()
            packet_id = event.get_packet_id()
            queue = self.model.get_module(queue_id)
            packet = self.model.get_packet(packet_id)
            packet.set_module(queue_id)
            queue.appendleft(packet)
            logger.info("%8.3f -- %s at node %s (qlen: %d), packet id: %s" %
                         (self.get_time(), event.etype, queue.name, len(queue), str(packet_id)))
            del event

            # if packet is first in the queue, inform the output module of this
            if len(queue) == 1:
                destination = gu.choose_output(queue.outputs)
                if destination is None:
                    # Current module has no outputs
                    return

                if type(destination) == Server and not destination.busy:
                    # move packet to server
                    event = Event(
                        timestamp=self.get_time(),
                        etype='SERVER_PACKET_ARRIVAL',
                        module_id=id(destination),
                        packet_id=packet_id
                    )
                    self.add_event(event)
                    queue.pop()
                elif type(destination) == Queue:
                    # Schedule a queue packet arrival event
                    event = Event(
                        timestamp=self.get_time(),
                        etype='QUEUE_PACKET_ARRIVAL',
                        module_id=id(destination),
                        packet_id=id(packet)
                    )
                    self.add_event(event)
                    queue.pop()

        elif event.etype == 'SERVER_PACKET_ARRIVAL':
            server_id = event.get_module_id()
            packet_id = event.get_packet_id()
            server = self.model.get_module(server_id)
            packet = self.model.get_packet(packet_id)
            packet.set_module(server_id)

            if not server.busy:
                server.busy = True

            # Schedule service end time
            service_duration = np.random.exponential(1 / server.service_rate)

            logger.info("%8.3f -- %s at node %s, packet id: %s, service duration: %.3f" %
                         (self.get_time(), event.etype, server.name, str(packet_id), service_duration))
            del event

            timestamp = service_duration + self.get_time()
            event = Event(
                timestamp=timestamp,
                etype='SERVICE_COMPLETE',
                module_id=server_id,
                packet_id=packet_id
            )
            self.add_event(event)

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

        # End of simulation
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

        if type(module) == Source:
            self.sources[id(module)] = module

    def get_module(self, module_id):
        return self.modules[module_id]

    def get_modules(self):
        return list(self.modules.values())

    def get_sources(self):
        return list(self.sources.values())

    def add_packet(self, packet):
        self.packets[id(packet)] = packet

    def get_packet(self, packet_id):
        return self.packets[packet_id]


if __name__ == '__main__':

    sim = Simulation(duration=50)
    m = Model(name='model1')

    # Declare model's components
    q1 = Queue(name='q1')
    s1 = Server(name='s1', service_rate=0.2)
    q2 = Queue(name='destination')

    # Add component's inputs and outputs
    gen = Source(rate=5, outputs=[{'module': q1, 'prob': 1}], name='gen')
    q1.outputs = [{'module': s1, 'prob': 1}]
    s1.inputs = [{'module': q1, 'prob': 1}]
    s1.outputs = [{'module': q2, 'prob': 1}]

    # Register components to model
    m = Model()
    m.add_module(q1)
    m.add_module(s1)
    m.add_module(q2)
    m.add_module(gen)

    # Register model with simulation.
    # This also registers all model's modules with simulation.
    sim.add_model(m)
    sim.run()
