
"""
Plot results of the simulation
"""

import pandas as pd
import numpy as np
from plotly.offline import plot
import plotly.graph_objs as go


def get_data_utilisation(results_file, module_id=None, module_name=None):
    df = pd.read_csv(results_file, index_col=0)
    df = df.astype({'module_id': str, 'packet_id': str})

    if module_id:
        data = df.loc[df['module_id'] == module_id]
    elif module_name:
        data = df.loc[df['module_name'] == module_name]

    events1 = pd.DataFrame()
    events1['time'] = data['arrival_time']
    events1['packets'] = [1] * len(data)

    events2 = pd.DataFrame()
    events2['time'] = data['departure_time']
    events2['packets'] = [-1] * len(data)

    events = events1.merge(events2, how='outer')
    events.sort_values(by='time', inplace=True)

    # sum up total packets in the module
    sum_pkts = []
    sum_ = 0
    for i in range(len(events)):
        event = events.iloc[i]
        val = event.packets
        time = event.time
        if str(time) != 'nan':
            sum_ += val
        sum_pkts.append(sum_)

    events['sum_pkts'] = sum_pkts

    return events


def plot_module_utilisation(results_file, module_id=None, module_name=None):
    if module_id is None and module_name is None:
        raise ValueError("Please provide either a module_id or module_name.")

    data = get_data_utilisation(results_file, module_id, module_name)

    t = go.Scatter(x=data['time'], y=data['sum_pkts'], mode="lines+markers", line={'shape': 'hv'})
    if module_id:
        title = 'Number of packets over time | module id: %s' % str(module_id)
    elif module_name:
        title = 'Number of packets over time | module: %s' % module_name

    layout = go.Layout(title=title,
                       xaxis=dict(title="Simulation time"))
    figure = go.Figure(data=[t], layout=layout)
    plot(figure)


# Todo: plot all results given a simulation name and store figures in a single place


if __name__ == '__main__':
    plot_module_utilisation(results_file='results_190404-140011.csv', module_name='s1')  #, module_id='2726695503576')

