
"""
Plot results of the simulation
"""

import pandas as pd


def plot_module_utilisation(results_file, module_id=None, module_name=None):
    if module_id is None and module_name is None:
        raise ValueError("Please provide either a module_id or module_name.")

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
    events2['time'] = data['arrival_time']
    events2['packets'] = [-1] * len(data)

    # todo: merge
    events = pd.merge([events1, events2], right=events2)

    print(events)


if __name__ == '__main__':
    plot_module_utilisation(results_file='results_190402-160528.csv', module_id='2726695503576')

