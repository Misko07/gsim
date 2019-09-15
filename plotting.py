
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
        data_normal = df[(df['module_id'] == module_id) & (df['malicious'] == False) & (df['permit'] == False) &
                         (df['neg_signal'] == False)]
        data_malicious = df.loc[(df['module_id'] == module_id) & (df['malicious'] == True)]
        data_negsig = df.loc[(df['module_id'] == module_id) & (df['neg_signal'] == True)]
        data_permit = df.loc[(df['module_id'] == module_id) & (df['permit'] == True)]
    elif module_name:
        data_normal = df[(df['module_name'] == module_name) & (df['malicious'] == False) & (df['permit'] == False) &
                         (df['neg_signal'] == False)]
        data_malicious = df.loc[(df['module_name'] == module_name) & (df['malicious'] == True)]
        data_negsig = df.loc[(df['module_name'] == module_name) & (df['neg_signal'] == True)]
        data_permit = df.loc[(df['module_name'] == module_name) & (df['permit'] == True)]

    print('data_negsig len: ', len(data_negsig))

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

    # Events for permit traffic
    arrivals_permit = pd.DataFrame()
    departures_permit = pd.DataFrame()
    removals_permit = pd.DataFrame()
    arrivals_permit['time'] = data_permit['arrival_time']
    arrivals_permit['packets'] = [1] * len(data_permit)
    departures_permit['time'] = data_permit['departure_time']
    departures_permit['packets'] = [-1] * len(data_permit)
    removals_permit['time'] = data_permit['removal_time']
    removals_permit['packets'] = [-1] * len(data_permit)
    removals_permit.dropna(inplace=True)
    events_permit = arrivals_permit.merge(departures_permit, how='outer')
    print('events permit len:', len(events_permit))
    events_permit = events_permit.merge(removals_permit, how='outer')
    events_permit.sort_values(by='time', inplace=True)
    # Todo: correct the merging here! This duplicates data

    print('events permit len:', len(events_permit))

    # Events for negative signals traffic
    arrivals_negsig = pd.DataFrame()
    departures_negsig = pd.DataFrame()
    arrivals_negsig['time'] = data_negsig['arrival_time']
    arrivals_negsig['packets'] = [1] * len(data_negsig)
    departures_negsig['time'] = data_negsig['arrival_time']
    departures_negsig['packets'] = [-1] * len(data_negsig)
    events_negsig = arrivals_negsig.merge(departures_negsig, how='outer')
    events_negsig.sort_values(by='time', inplace=True)

    events_all = pd.concat([events_mal, events_normal, events_permit, events_negsig])
    events_all.sort_values(by='time', inplace=True)

    events_normal = cumulative_arrivals(events_normal)
    events_mal = cumulative_arrivals(events_mal)
    events_permit = cumulative_arrivals(events_permit)
    events_negsig = cumulative_arrivals(events_negsig)
    events_all = cumulative_arrivals(events_all)

    # events_fin.to_csv('results/vec_%s.csv' % module_name)

    print('malicious', events_mal.shape)
    print('normal', events_normal.shape)
    print('permits', events_permit.shape)
    print('negsig', events_negsig.shape)

    return events_normal, events_mal, events_permit, events_negsig, events_all


def plot_module_utilisation(results_file, module_id=None, module_name=None):
    if module_id is None and module_name is None:
        raise ValueError("Please provide either a module_id or module_name.")

    data_norm, data_mal, data_permit, data_negsig, data_all = get_data_utilisation(results_file, module_id, module_name)

    t1 = go.Scatter(x=data_norm['time'], y=data_norm['sum_pkts'], mode="lines+markers", line={'shape': 'hv'}, name='Normal')
    t2 = go.Scatter(x=data_mal['time'], y=data_mal['sum_pkts'], mode="lines+markers", line={'shape': 'hv'}, name='Malicious')
    t3 = go.Scatter(x=data_permit['time'], y=data_permit['sum_pkts'], mode="lines+markers", line={'shape': 'hv'}, name='Permits')
    t4 = go.Scatter(x=data_negsig['time'], y=data_negsig['sum_pkts'], mode="lines+markers", line={'shape': 'hv'},
                    name='Neg. signals')
    t5 = go.Scatter(x=data_all['time'], y=data_all['sum_pkts'], mode="lines+markers", line={'shape': 'hv'}, name='All')
    if module_id:
        title = 'Number of packets over time | module id: %s' % str(module_id)
    elif module_name:
        title = 'Number of packets over time | module: %s' % module_name

    layout = go.Layout(title=title,
                       xaxis=dict(title="Simulation time"))
    figure = go.Figure(data=[t1, t2, t3, t4, t5], layout=layout)
    plot(figure)


# Todo: plot all results given a simulation name and store figures in a single place


if __name__ == '__main__':
    plot_module_utilisation(results_file='results/vec-190912-113454.csv', module_name='qp')  # module_id='2530220349256')  #  module_name='q2'
