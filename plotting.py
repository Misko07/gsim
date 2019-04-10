
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
        data_normal = df.loc[(df['module_id'] == module_id) & (df['malicious'] is False)]
        data_malicious = df.loc[(df['module_id'] == module_id) & (df['malicious'] is False)]
    elif module_name:
        data_normal = df.loc[(df['module_name'] == module_name) & (df['malicious'] is False)]
        data_malicious = df.loc[(df['module_name'] == module_name) & (df['malicious'] is True)]

    # todo: continue from here - track both malicious and normal data
    # arrivals
    arrivals_normal = pd.DataFrame()
    arrivals_normal['time'] = data_normal['arrival_time']
    arrivals_normal['packets'] = [1] * len(data_normal)

    # departures
    departures_normal = pd.DataFrame()
    departures_normal['time'] = data_normal['departure_time']
    departures_normal['packets'] = [-1] * len(data_normal)

    events = arrivals_normal.merge(departures_normal, how='outer')
    events.sort_values(by='time', inplace=True)

    # sum up total packets in the module
    data_util = {'time': [], 'sum_pkts': []}
    sum_ = 0
    prev_time = 0
    for i in range(len(events)):
        event = events.iloc[i]
        val = event.packets
        time_ = event.time
        if time_ != prev_time:
            data_util['sum_pkts'].append(sum_)
            data_util['time'].append(prev_time)
        if str(time_) != 'nan':
            sum_ += val
        prev_time = time_

    events_fin = pd.DataFrame(data_util, columns=list(data_util.keys()))
    # events_fin.to_csv('results/vec_%s.csv' % module_name)

    return events_fin


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
    plot_module_utilisation(results_file='results/vec-190404-143933.csv', module_id='2530220349256')  #  module_name='q2'

