
"""
Plot results of the simulation
"""

import pandas as pd
from plotly.offline import plot
import plotly.graph_objs as go


def cumulative_arrivals(events_df):
    # sum up total packets in the module
    data_util = {'time': [], 'sum_pkts': []}
    sum_ = 0
    prev_time = 0
    for i in range(len(events_df)):
        event = events_df.iloc[i]
        val = event.packets
        time_ = event.time
        if time_ != prev_time:
            data_util['sum_pkts'].append(sum_)
            data_util['time'].append(prev_time)
        if str(time_) != 'nan':
            sum_ += val
        prev_time = time_

    events_fin = pd.DataFrame(data_util, columns=list(data_util.keys()))
    return events_fin


def get_data_utilisation(results_file, module_id=None, module_name=None):
    df = pd.read_csv(results_file, index_col=0)
    df = df.astype({'module_id': str, 'packet_id': str})

    if module_id:
        data_normal = df[(df['module_id'] == module_id) & (df['malicious'] == False)]
        data_malicious = df.loc[(df['module_id'] == module_id) & (df['malicious'] == True)]
    elif module_name:
        data_normal = df[(df['module_name'] == module_name) & (df['malicious'] == False)]
        data_malicious = df.loc[(df['module_name'] == module_name) & (df['malicious'] == True)]

    # Events for normal traffic
    arrivals_normal = pd.DataFrame()
    departures_normal = pd.DataFrame()
    arrivals_normal['time'] = data_normal['arrival_time']
    arrivals_normal['packets'] = [1] * len(data_normal)
    departures_normal['time'] = data_normal['departure_time']
    departures_normal['packets'] = [-1] * len(data_normal)
    events_normal = arrivals_normal.merge(departures_normal, how='outer')
    events_normal.sort_values(by='time', inplace=True)

    # Events for malicious traffic
    arrivals_mal = pd.DataFrame()
    departures_mal = pd.DataFrame()
    arrivals_mal['time'] = data_malicious['arrival_time']
    arrivals_mal['packets'] = [1] * len(data_malicious)
    departures_mal['time'] = data_malicious['departure_time']
    departures_mal['packets'] = [-1] * len(data_malicious)
    events_mal = arrivals_mal.merge(departures_mal, how='outer')
    events_mal.sort_values(by='time', inplace=True)

    events_all = pd.concat([events_mal, events_normal])
    events_all.sort_values(by='time', inplace=True)

    events_normal = cumulative_arrivals(events_normal)
    events_mal = cumulative_arrivals(events_mal)
    events_all = cumulative_arrivals(events_all)

    # events_fin.to_csv('results/vec_%s.csv' % module_name)

    print(events_mal.shape)
    print(events_normal.shape)

    return events_normal, events_mal, events_all


def plot_module_utilisation(results_file, module_id=None, module_name=None):
    if module_id is None and module_name is None:
        raise ValueError("Please provide either a module_id or module_name.")

    data_norm, data_mal, data_all = get_data_utilisation(results_file, module_id, module_name)

    t1 = go.Scatter(x=data_norm['time'], y=data_norm['sum_pkts'], mode="lines+markers", line={'shape': 'hv'}, name='Normal')
    t2 = go.Scatter(x=data_mal['time'], y=data_mal['sum_pkts'], mode="lines+markers", line={'shape': 'hv'}, name='Malicious')
    t3 = go.Scatter(x=data_all['time'], y=data_all['sum_pkts'], mode="lines+markers", line={'shape': 'hv'},
                    name='All')
    if module_id:
        title = 'Number of packets over time | module id: %s' % str(module_id)
    elif module_name:
        title = 'Number of packets over time | module: %s' % module_name

    layout = go.Layout(title=title,
                       xaxis=dict(title="Simulation time"))
    figure = go.Figure(data=[t1, t2, t3], layout=layout)
    plot(figure)


# Todo: plot all results given a simulation name and store figures in a single place


if __name__ == '__main__':
    plot_module_utilisation(results_file='results/vec-190904-162912.csv', module_name='q1')  # module_id='2530220349256')  #  module_name='q2'

10