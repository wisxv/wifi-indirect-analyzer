import decimal as dec
import os
import subprocess
import time
from collections import Counter
from datetime import datetime

import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import seaborn as sns
from pyvis.network import Network
from rich.console import Console

# rich console for parser output
console = Console()


def epoch_min_to_week_number(epoch_min: int) -> int:
    """
    Converts unix time in minutes to week relative week number
    """
    dt = datetime.utcfromtimestamp(epoch_min * 60)  # to seconds
    epoch_start = datetime.utcfromtimestamp(0)
    weeks_since_epoch = (dt - epoch_start).days // 7
    return weeks_since_epoch


class TsharkNotInstalledException(Exception):
    """
    raised if tshark is not installed
    """

    def __init__(self, message="You should install tshark before importing any file"):
        self.message = message
        super().__init__(self.message)


class Parser:
    """
    Importing cap/pcap/pcapng file(s) using wireshark
    """

    def __init__(self):
        # check if wireshark is installed
        try:
            subprocess.check_output('tshark -v', shell=True)
        except subprocess.CalledProcessError:
            raise TsharkNotInstalledException()

        self.aps = set()  # Access points
        self.aps_requested = set()  # Requests to apps that are note reachable
        self.stations = dict()  # known stations
        self.channels = dict()  # parsed channels stats
        self.packets_counter = 0  # packet counter (not used now)
        self.merged_filename = 'merged.pcap'

    def parse(self, filenames: list, parse_pwr: bool = False) -> None:
        """
        Logical wrapper above low-lvl functions for extracting data
        """
        with console.status('Working...', spinner='point') as status:
            status.update('Preparing files...')
            self.__merge(filenames)
            status.update('Counting packets...')
            self.__get_count()
            status.update('Extracting channels data...')
            self.__get_channels()
            status.update('Determining devices...')
            self.__get_devices(parse_pwr)
            status.update('Done!', spinner='star')
            time.sleep(1.5)

    def __merge(self, filenames: list) -> None:
        """
        merge files to 1 if given >1 files using mergecap
        """
        if len(filenames) > 1:
            command = 'mergecap' + ' ' + ' '.join(filenames) + ' -w ' + self.merged_filename
            os.system(command)
        elif len(filenames) == 1:
            self.merged_filename = filenames[0]

    def __get_devices(self, parse_pwr: bool = False) -> None:
        """
        Determine aps and stations using data from listed types of frames:
        - beacon
        - association request/response
        - probe request/response
        - data
        """

        # Wireshark filters
        f_bcn = "(wlan.fc.type == 0 and wlan.fc.subtype == 8)"
        f_aso_req = "(wlan.fc.type == 0 and wlan.fc.subtype == 0 and wlan.ssid)"
        f_ass_rsp = "(wlan.fc.type == 0 and wlan.fc.subtype == 1 and wlan.ssid)"
        f_pro_req = "(wlan.fc.type == 0 and wlan.fc.subtype == 4 and wlan.ssid)"
        f_pro_rsp = "(wlan.fc.type == 0 and wlan.fc.subtype == 5 and wlan.ssid)"
        # Exclude multicast destinations but not for beacons
        f_not_mcst = "!(wlan.da[0] & 1)"
        f_data = "(wlan.fc.type == 2)"
        f_fields = '-e wlan.fc.type -e wlan.fc.subtype -e radiotap.dbm_antsignal ' \
                   '-e frame.time_epoch -e wlan.sa -e wlan.da -e wlan.ssid'
        # RadioTap header sometimes have multiple same-called fields
        f_opts = '-E occurrence=f -E separator=","'
        f_final = f'{f_bcn} or (({f_pro_rsp} ' \
                  f'or {f_aso_req} or {f_ass_rsp} or {f_data}) and {f_not_mcst}) or {f_pro_req}'

        # Final filter command
        command = f'tshark -r {self.merged_filename} -Y "{f_final}" -T fields {f_fields} {f_opts}'

        # Run tshark in shell, get, format output
        pkts = subprocess.check_output(command, shell=True, text=True).split('\n')
        pkts = list(filter(None, pkts))
        if len(pkts) > 0:

            # Separate frames by types
            pkts = [i for i in [y.split(',') for y in set(pkts)]]
            aps_bcn_hidden = set()
            if parse_pwr:
                beacons = [(i[2], i[4], i[-1]) for i in pkts if i[0] == '0' and i[1] == '8' and '-' in i[2]]
            else:
                beacons = [(i[4], i[-1]) for i in pkts if i[0] == '0' and i[1] == '8']
            assoc = set([(i[1], i[4], i[5], i[6]) for i in pkts if i[0] == '0' and (i[1] == '0' or i[1] == '1')])
            probe = set([(i[1], i[4], i[5], i[6]) for i in pkts if i[0] == '0' and (i[1] == '4' or i[1] == '5')])
            data = [(i[3].split('.')[0], i[4], i[5]) for i in pkts if i[0] == '2']

            # Get aps from beacons
            if len(beacons) > 0:
                aps_bcn = set()
                for f in beacons:
                    if parse_pwr:
                        pwr, bssid, ssid = f
                    else:
                        # noinspection PyTupleAssignmentBalance
                        bssid, ssid = f
                    if ssid == '<MISSING>':
                        ssid = None
                    if not ((bssid, ssid) in aps_bcn):
                        aps_bcn.add((bssid, ssid))
                if len(aps_bcn) > 0:
                    # Check if already have bssid for any ap
                    for note in aps_bcn:
                        if note[-1] is not None:
                            if (note[0], None) in aps_bcn:
                                aps_bcn.remove((note[0], None))
                    if parse_pwr:
                        # Count average power level
                        for note in aps_bcn:
                            power_sum, counter = 0, 0
                            for f in beacons:
                                if f[1] == note[0]:
                                    counter += 1
                                    power_sum += int(f[0])
                            ap_note = (note[0], note[1], int(round(power_sum / counter, 2)))
                            if note[1] is not None:
                                self.aps.add(ap_note)
                            else:
                                # If still can't determine ssid
                                aps_bcn_hidden.add(ap_note)
                    else:
                        for note in aps_bcn:
                            ap_note = (note[0], note[1])
                            if note[1] is not None:
                                self.aps.add(ap_note)
                            else:
                                aps_bcn_hidden.add(ap_note)

            # Try to find out bssid for hidden aps from association requests
            if len(aps_bcn_hidden) > 0:
                to_remove_aps_bcn_hidden = list()
                if len(assoc) > 0:
                    if len(self.aps) > 0:
                        assoc = set([i for i in assoc if not any((i[-1] == y[1]) for y in self.aps)])
                    if len(assoc) > 0:
                        for i in assoc:
                            subtype, src, dst, ap_ssid = i
                            ap_bssid = None
                            if subtype == '0':  # request
                                ap_bssid = dst
                            elif subtype == '1':  # response
                                ap_bssid = src
                            if parse_pwr:
                                for note in aps_bcn_hidden:
                                    if ap_bssid == note[0]:
                                        to_remove_aps_bcn_hidden.append(note)
                                        self.aps.add((ap_bssid, ap_ssid, note[-1]))
                            else:
                                for note in aps_bcn_hidden:
                                    if ap_bssid == note[0]:
                                        to_remove_aps_bcn_hidden.append(note)
                                        self.aps.add((ap_bssid, ap_ssid))
                if len(to_remove_aps_bcn_hidden) > 0:
                    [aps_bcn_hidden.remove(i) for i in to_remove_aps_bcn_hidden]

            # Trying to find out hidden aps bssid and remember requested aps that are not reachable
            if len(probe) > 0:
                if len(self.aps) > 0:
                    # With bssid only
                    probe = [i for i in probe if not (any((i[-1] == y[-2]) for y in self.aps)) and i[-1] != '<MISSING>']
                if len(probe) > 0:
                    for i in probe:
                        subtype, src, dst, ssid = i
                        if len(aps_bcn_hidden) > 0:
                            is_hidden = False
                            to_remove_bcn_hidden = list()
                            to_remove_probe = list()
                            for y in aps_bcn_hidden:
                                if y[0] == dst:
                                    is_hidden = True
                                    to_remove_bcn_hidden.append(y)
                                    aps_bcn_hidden.add((dst, ssid, y[-1]))
                                    for p in probe:
                                        if dst in p:
                                            to_remove_probe.append(p)
                            if len(to_remove_bcn_hidden) > 0:
                                [aps_bcn_hidden.remove(elem) for elem in to_remove_bcn_hidden]
                            if len(to_remove_probe) > 0:
                                [probe.remove(elem) for elem in to_remove_probe]
                            if not is_hidden and subtype == '4':
                                self.aps_requested.add((src, ssid))
                        else:
                            if subtype == '4':
                                self.aps_requested.add((src, ssid))

            # Add hidden aps to aps if failed to find out bssid
            if len(aps_bcn_hidden) > 0:
                [self.aps.add(i) for i in aps_bcn_hidden]

            # Find stations and aps they connected to by data frames
            if len(self.aps) > 0 and len(data) > 0:
                for i in self.aps:
                    if parse_pwr:
                        ap_bssid, ap_ssid, ap_pwr = i
                    else:
                        ap_bssid, ap_ssid = i
                    for f in data:
                        f_time, src, dst = f
                        sta_mac = None
                        if ap_bssid == src:
                            sta_mac = dst
                        elif ap_bssid == dst:
                            sta_mac = src

                        # There can be multiple aps for each station
                        # Also count frames/unix_time_minute
                        if sta_mac is not None:
                            unix_t_min = int(f_time) // 60
                            if not (sta_mac in self.stations):
                                self.stations[sta_mac] = {}
                                self.stations[sta_mac][i] = {}
                                self.stations[sta_mac][i][unix_t_min] = 1
                            elif sta_mac in self.stations:
                                if not (i in self.stations[sta_mac]):
                                    self.stations[sta_mac][i] = {}
                                    self.stations[sta_mac][i][unix_t_min] = 1
                                else:
                                    if unix_t_min in self.stations[sta_mac][i]:
                                        self.stations[sta_mac][i][unix_t_min] += 1
                                    else:
                                        self.stations[sta_mac][i][unix_t_min] = 1

            if len(self.aps_requested) > 0:
                for note in self.aps_requested:
                    # Add ap to aps
                    self.aps.add((None, note[-1]))
                    if not note[0] in self.stations:
                        self.stations[note[0]] = {}
                    # Add app to station that belongs to it
                    self.stations[note[0]][(None, note[-1])] = {}

    def __get_channels(self) -> None:
        """
        Collect channel for every frame
        """
        f_cmd = f'tshark -r {self.merged_filename} -Y "wlan_radio.channel" -T fields -e wlan_radio.channel'
        channel_data = subprocess.check_output(f_cmd, shell=True, text=True).split('\n')
        channel_data = list(filter(None, channel_data))
        if len(channel_data) > 0:
            channel_data = [int(i) for i in channel_data]
            self.channels = dict(Counter(channel_data))

    def __get_count(self) -> None:
        """
        Get packets count
        """
        f_cmd = f'tshark -r {self.merged_filename} -n | wc -l'
        packets_count = subprocess.check_output(f_cmd, shell=True, text=True)
        if len(packets_count) > 0:
            packets_count = int(packets_count.strip())
            self.packets_counter = packets_count


class Statistics:
    """
    Any presentation and data preparation job
    """

    def __init__(self, parser: Parser):
        self.aps = parser.aps
        self.aps_requested = parser.aps_requested
        self.stations = parser.stations
        self.channels = parser.channels
        self.packets_counter = parser.packets_counter
        self.prob_reordered_sta = dict()
        self.fixed_ap_struct_str = tuple()
        self.fixed_ap_struct = None

    def graph(self, parse_pwr=False, radial=False) -> None:
        def generate_next_integer():
            current_integer = 1
            while True:
                yield current_integer
                current_integer += 1

        def generate_next_alphabetical_string():
            current_string = 'a'
            while True:
                yield current_string
                current_string = increment_string(current_string)

        def increment_string(s):
            if not s:
                return 'a'
            last_char = s[-1]
            if last_char < 'z':
                return s[:-1] + chr(ord(last_char) + 1)
            else:
                return increment_string(s[:-1]) + 'a'

        # Assign generator functions to variables
        generator_ap = generate_next_alphabetical_string()
        generator_st = generate_next_integer()

        # Link devices to ids;pyvis node IDs can only be integers or strings
        node_links = {}
        for ap in self.aps:
            node_links[next(generator_ap)] = ap
        for station in self.stations:
            node_links[next(generator_st)] = station
        node_links_reverse = {value: key for key, value in node_links.items()}

        ap_values = dict()
        nodes, edges = list(), list()
        for ap in self.aps:
            # Node value = packets count for this AP
            ap_value_counter = 10  # start value is magic!
            for station in self.stations:
                if ap in self.stations[station]:
                    ap_value_counter += sum((self.stations[station][ap]).values())
            color = '#22ff31'  # active ap
            if ap[0] is None:
                color = '#ff9f22'  # requested unreachable ap
            if ap[1] is not None:
                name = bytes.fromhex(ap[1]).decode('utf-8', 'ignore')  # decode bssid
            else:
                name = '<unknown>'
                color = '#ff3222'  # hidden ap
            if parse_pwr:
                title = f'{name}\n{ap[0]}\npower:{ap[-1]}'
            else:
                title = f'{name}\n{ap[0]}'
            nodes.append((node_links_reverse[ap],
                          {'color': color,
                           'value': ap_value_counter,
                           'title': title}))
            ap_values[node_links_reverse[ap]] = ap_value_counter

        # Add stations
        for link in node_links:
            if type(link) == int:
                nodes.append((link, {'color': '#22f0ff', 'title': node_links[link], 'label': str(link)}))

        # Add edges
        for station in self.stations:
            station_aps = self.stations[station]
            if len(station_aps) > 0:
                for i in station_aps:
                    # shows station's activity for AP
                    sta_weight = sum((station_aps[i].values())) / ap_values[node_links_reverse[i]]
                    edges.append((node_links_reverse[i],
                                  node_links_reverse[station],
                                  {'weight': sta_weight}))
        # Create graph
        g = nx.Graph()
        g.add_nodes_from(nodes)
        g.add_edges_from(edges)

        # Not supported yet. Useless due to impossibility of drawing distances in vispy
        if radial:
            # add 'You' node; 'You - Ap' edges
            g.add_node(0, color='black', title='You')
            for i in self.aps:
                if len(i) == 3:
                    length = (100 + int(i[-1])) / 10
                    g.add_edge(0, node_links_reverse[i], weight=0.1, hidden=True, length=length)

        nt = Network(height="900", width="100%", filter_menu=True, select_menu=True)
        nt.from_nx(g)
        nt.toggle_physics(True)
        nt.show_buttons(filter_=['physics'])
        nt.show('graph.html', notebook=False, local=True)

    def heatmap(self) -> None:
        """
        Heatmap of channels utilization
        """
        self.channels = dict(sorted(self.channels.items(), key=lambda x: x[0]))
        channel_utilization_matrix = np.array([list(self.channels.values())])
        normalized_matrix = channel_utilization_matrix / np.sum(channel_utilization_matrix)
        fig, ax = plt.subplots(figsize=(12, 4))
        heatmap = sns.heatmap(normalized_matrix, annot=True, cmap='viridis',
                              xticklabels=list(self.channels.keys()),
                              yticklabels=['Channel Utilization'])
        plt.xlabel('Wi-Fi Channel')
        plt.title('Wi-Fi Channel Utilization Heatmap')
        fig.savefig('heatmap.png', bbox_inches='tight')
        plt.show()

    def reorder_sta_weeks(self) -> None:
        """
        Rebuild stations dictionary this way: {'<station>':{'<ap>':{<day_of_the_week>: <count>, ...}, ...}, ...}
        """
        for sta in self.stations:
            if len(self.stations[sta]) > 0:
                for ap_note in self.stations[sta]:
                    if ap_note[0] is not None:
                        tmp = set()
                        for i in self.stations[sta][ap_note]:
                            week_num = epoch_min_to_week_number(i)
                            day_of_the_week = time.strftime('%A', time.localtime(i * 60))
                            tmp.add((week_num, day_of_the_week))
                        week_days = [day for _, day in list(tmp)]
                        counted_week_days = dict(Counter(week_days))
                        try:
                            ap_renamed_utf8 = (ap_note[0], bytes.fromhex(ap_note[1]).decode('utf-8', 'ignore'))
                        except TypeError:
                            ap_renamed_utf8 = (ap_note[0], '<unknown>')
                        if sta in self.prob_reordered_sta:
                            self.prob_reordered_sta[sta][ap_renamed_utf8] = counted_week_days
                        else:
                            self.prob_reordered_sta[sta] = {}
                            self.prob_reordered_sta[sta][ap_renamed_utf8] = counted_week_days

    def stations_available(self) -> list:
        return list(self.prob_reordered_sta.keys())

    def aps_available(self, station: str) -> tuple:
        # convert ap notes (tuple) to (str) TODO pwr support
        self.fixed_ap_struct = tuple(self.prob_reordered_sta[station].keys())
        self.fixed_ap_struct_str = tuple(f'{i[0]} - {i[1]}' for i in self.fixed_ap_struct)

        return self.fixed_ap_struct_str

    def week_probability_plot(self, station: str, ap: str) -> None:
        """
        Draw a plot of Probability distribution of appearance selected STA for selected AP
        Using: P = <day_of_the_week_count> / <all_the_time_count>
        """
        selected_ap_id = self.fixed_ap_struct_str.index(ap)
        selected_ap = self.fixed_ap_struct[selected_ap_id]
        days_of_the_week = ('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')
        x_y_dict = {x: 0 for x in days_of_the_week}
        dec.getcontext().prec = 10
        for day, count in (self.prob_reordered_sta[station][selected_ap]).items():
            if day in x_y_dict:
                probability = dec.Decimal(dec.Decimal(count) /
                    (dec.Decimal(sum(
                        self.prob_reordered_sta[station][selected_ap].values()
                    ))))
                two_places = dec.Decimal('0.01')
                probability = probability.quantize(two_places)
                x_y_dict[day] = probability
        probabilities = [x_y_dict[i] for i in days_of_the_week]

        sns.barplot(x=days_of_the_week, y=probabilities)
        plt.xlabel('Day')
        plt.ylabel('Probability')
        plt.title(f'Probability distribution of appearance \nSTA {station}\nfor AP {ap}\nweekly')
        filename = ''.join(
            f'device_{station}_for_ap_{ap}_probability_distribution'.split(':')
            )
        plt.savefig(f'{filename}.png', bbox_inches='tight')
        plt.show()
