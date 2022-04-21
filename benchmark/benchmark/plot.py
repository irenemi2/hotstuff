from re import findall, search
import matplotlib.pyplot as plt
from matplotlib.ticker import StrMethodFormatter
from glob import glob

from benchmark.utils import PathMaker


class PlotError(Exception):
    pass


class Ploter:
    def __init__(self, filenames):
        if not filenames:
            raise PlotError('No data to plot')

        self.results = []
        try:
            for filename in filenames:
                with open(filename, 'r') as f:
                    self.results += [f.read().replace(',', '')]
        except OSError as e:
            raise PlotError(f'Failed to load log files: {e}')

    def _tps(self, data):
        values = findall(r' TPS: (\d+) \+/- (\d+)', data)
        values = [(int(x), int(y)) for x, y in values]
        return list(zip(*values))

    def _latency(self, data, scale=1):
        values = findall(r' Latency: (\d+) \+/- (\d+)', data)
        values = [(float(x)/scale, float(y)/scale) for x, y in values]
        print(list(zip(*values)))
        return list(zip(*values))

    def _variable(self, data):
        return [int(x) for x in findall(r'Variable value: X=(\d+)', data)]

    def _tps2bps(self, x):
        data = self.results[0]
        size = int(search(r'Transaction size: (\d+)', data).group(1))
        return x * size / 10**6

    def _bps2tps(self, x):
        data = self.results[0]
        size = int(search(r'Transaction size: (\d+)', data).group(1))
        return x * 10**6 / size

    def _plot(self, x_label, y_label, y_axis, z_axis, filename):
        plt.figure()
        for result in self.results:
            y_values, y_err = y_axis(result)
            x_values = self._variable(result)
            if len(y_values) != len(y_err) or len(y_err) != len(x_values):
                raise PlotError('Unequal number of x, y, and y_err values')

            plt.errorbar(
                x_values, y_values, yerr=y_err,  # uplims=True, lolims=True,
                marker='o', label=z_axis(result), linestyle='dotted'
            )

        plt.xlim(xmin=0)
        plt.ylim(bottom=0)
        plt.xlabel(x_label)
        plt.ylabel(y_label[0])
        plt.legend(loc='upper right')
        ax = plt.gca()
        ax.xaxis.set_major_formatter(StrMethodFormatter('{x:,.0f}'))
        ax.yaxis.set_major_formatter(StrMethodFormatter('{x:,.0f}'))
        if len(y_label) > 1:
            secaxy = ax.secondary_yaxis(
                'right', functions=(self._tps2bps, self._bps2tps)
            )
            secaxy.set_ylabel(y_label[1])
            secaxy.yaxis.set_major_formatter(StrMethodFormatter('{x:,.0f}'))

        for x in ['pdf', 'png']:
            plt.savefig(PathMaker.plot_file(filename, x), bbox_inches='tight')

    @staticmethod
    def nodes(data):
        x = search(r'Committee size: (\d+)', data).group(1)
        return f'{x} nodes'

    @staticmethod
    def tx_size(data):
        return search(r'Transaction size: .*', data).group(0)

    @classmethod
    def plot_robustness(cls, z_axis):
        assert hasattr(z_axis, '__call__')
        x_label = 'Input rate (tx/s)'
        y_label = ['Throughput (tx/s)', 'Throughput (MB/s)']

        files = glob(PathMaker.agg_file(r'[0-9]*', 'x', r'*'))
        ploter = cls(files)
        ploter._plot(x_label, y_label, ploter._tps, z_axis, 'robustness')

    @classmethod
    def plot_latency(cls, z_axis):
        assert hasattr(z_axis, '__call__')
        x_label = 'Throughput (tx/s)'
        y_label = ['Latency (ms)']

        files = glob(PathMaker.agg_file(r'[0-9]*', 'any', r'*'))
        ploter = cls(files)
        ploter._plot(x_label, y_label, ploter._latency, z_axis, 'latency')

    @classmethod
    def plot_tps(cls, z_axis):
        assert hasattr(z_axis, '__call__')
        x_label = 'Committee size'
        y_label = ['Throughput (tx/s)', 'Throughput (MB/s)']

        files = glob(PathMaker.agg_file('x', 'any', r'*'))
        ploter = cls(files)
        ploter._plot(x_label, y_label, ploter._tps, z_axis, 'tps')
