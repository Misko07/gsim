import numpy as np


def choose_output(outputs):

    # Choose a destination module for the packet
    output_modules = [o['module'] for o in outputs]
    output_probs = [o['prob'] for o in outputs]
    index = np.random.choice(len(output_modules), output_probs)[0]
    return output_modules[index]
