import pyshark
import pickle
import numpy as np
import pandas as pd
from sklearn import preprocessing

labels = {0: 'BENIGN', 1: 'PortScan', 2: 'DDoS/DoS', 3: 'Web Attack', 4: 'Bot'}

cap = pyshark.LiveCapture(interface='en0', display_filter='tcp')
cap.sniff(timeout=0.5)
streams = []
src_dst = {}
packets = {}
current_backward_time = {}
bulk = {}
idle = {}

clf = pickle.load((open('random_forest_classifier.pickle', 'rb')))

def fwd_bwd(packet, packets):
    # Fwd Packet Length Min/Bwd Packet Length Min
    if packet[1].src in src_dst[packet[2].stream].keys():
        packets[packet[2].stream]['Fwd Packet Length Min'].append(int(packet[2].len))

        # Fwd Packets/s
        packets[packet[2].stream]['Fwd Packets/s'] += 1

        # min_seg_size_forward
        packets[packet[2].stream]['min_seg_size_forward'].append(int(packet[2].hdr_len))
    elif packet[1].src in src_dst[packet[2].stream].values():
        packets[packet[2].stream]['Bwd Packet Length Min'].append(int(packet[2].len))

        # Bwd IAT Std
        packets[packet[2].stream]['Bwd IAT Std'].append(
            float(packet[2].time_relative) - current_backward_time[packet[2].stream])
        current_backward_time[packet[2].stream] = float(packet[2].time_relative)

        # Bwd Packets/s
        packets[packet[2].stream]['Bwd Packets/s'] += 1


def flow(packet, packets):
    # Flow Bytes/s
    if 'analysis_push_bytes_sent' in dir(packet[2]):
        packets[packet[2].stream]['Flow Bytes/s'] += int(packet[2].analysis_push_bytes_sent)

    # Flow Packets/s
    packets[packet[2].stream]['Flow Packets/s'] += 1

def updateFlowBulk(packet, src_dst, bulk):
    if packet[1].src in src_dst[packet[2].stream].keys():
        updateForwardBulk(packet, bulk[packet[2].stream]['blastBulkTS'], bulk)
    elif packet[1].src in src_dst[packet[2].stream].values():
        updateBackwardBulk(packet, bulk[packet[2].stream]['flastBulkTS'], bulk)

def updateForwardBulk(packet, tsOflastBulkInOther, bulk):

    if 'analysis_push_bytes_sent' in dir(packet[2]):
        size = int(packet[2].analysis_push_bytes_sent)
    else:
        return

    if tsOflastBulkInOther > bulk[packet[2].stream]['fbulkStartHelper']:
        bulk[packet[2].stream]['fbulkStartHelper'] = 0
    if size <= 0:
        return

    if bulk[packet[2].stream]['fbulkStartHelper'] == 0:
            bulk[packet[2].stream]['fbulkStartHelper'] = float(packet[2].time_relative)
            bulk[packet[2].stream]['fbulkPacketCountHelper'] = 1
            bulk[packet[2].stream]['fbulkSizeHelper'] = size
            bulk[packet[2].stream]['flastBulkTS'] = float(packet[2].time_relative)
    else:
        if (float(packet[2].time_relative) - bulk[packet[2].stream]['flastBulkTS'])  > 1.0:
            bulk[packet[2].stream]['fbulkStartHelper'] = float(packet[2].time_relative)
            bulk[packet[2].stream]['flastBulkTS'] = float(packet[2].time_relative)
            bulk[packet[2].stream]['fbulkPacketCountHelper'] = 1
            bulk[packet[2].stream]['fbulkSizeHelper'] = size
        else:
            bulk[packet[2].stream]['fbulkPacketCountHelper'] += 1
            bulk[packet[2].stream]['fbulkSizeHelper'] += size
            if bulk[packet[2].stream]['fbulkPacketCountHelper'] == 4:
                bulk[packet[2].stream]['fbulkStateCount'] += 1
                bulk[packet[2].stream]['fbulkPacketCount'] += bulk[packet[2].stream]['fbulkPacketCountHelper']
                bulk[packet[2].stream]['fbulkSizeTotal'] += bulk[packet[2].stream]['fbulkSizeHelper']
                bulk[packet[2].stream]['fbulkDuration'] += float(packet[2].time_relative) - bulk[packet[2].stream]['fbulkStartHelper']
            elif bulk[packet[2].stream]['fbulkPacketCountHelper'] > 4:
                bulk[packet[2].stream]['fbulkPacketCount'] += 1
                bulk[packet[2].stream]['fbulkSizeTotal'] += size
                bulk[packet[2].stream]['fbulkDuration'] += float(packet[2].time_relative) - bulk[packet[2].stream]['flastBulkTS']
            bulk[packet[2].stream]['flastBulkTS'] = float(packet[2].time_relative)


def updateBackwardBulk(packet, tsOflastBulkInOther, bulk):
    if 'analysis_push_bytes_sent' in dir(packet[2]):
        size = int(packet[2].analysis_push_bytes_sent)
    else:
        return

    if tsOflastBulkInOther > bulk[packet[2].stream]['bbulkStartHelper']:
        bulk[packet[2].stream]['bbulkStartHelper'] = 0
    if size <= 0:
        return

    if bulk[packet[2].stream]['bbulkStartHelper'] == 0:
        bulk[packet[2].stream]['bbulkStartHelper'] = float(packet[2].time_relative)
        bulk[packet[2].stream]['bbulkPacketCountHelper'] = 1
        bulk[packet[2].stream]['bbulkSizeHelper'] = size
        bulk[packet[2].stream]['blastBulkTS'] = float(packet[2].time_relative)
    else:
        if (float(packet[2].time_relative) - bulk[packet[2].stream]['blastBulkTS']) > 1.0:
            bulk[packet[2].stream]['bbulkStartHelper'] = float(packet[2].time_relative)
            bulk[packet[2].stream]['blastBulkTS'] = float(packet[2].time_relative)
            bulk[packet[2].stream]['bbulkPacketCountHelper'] = 1
            bulk[packet[2].stream]['bbulkSizeHelper'] = size
        else:
            bulk[packet[2].stream]['bbulkPacketCountHelper'] += 1
            bulk[packet[2].stream]['bbulkSizeHelper'] += size
            if bulk[packet[2].stream]['bbulkPacketCountHelper'] == 4:
                bulk[packet[2].stream]['bbulkStateCount'] += 1
                bulk[packet[2].stream]['bbulkPacketCount'] += bulk[packet[2].stream]['bbulkPacketCountHelper']
                bulk[packet[2].stream]['bbulkSizeTotal'] += bulk[packet[2].stream]['bbulkSizeHelper']
                bulk[packet[2].stream]['bbulkDuration'] += float(packet[2].time_relative) - bulk[packet[2].stream]['bbulkStartHelper']
            elif bulk[packet[2].stream]['fbulkPacketCountHelper'] > 4:
                bulk[packet[2].stream]['bbulkPacketCount'] += 1
                bulk[packet[2].stream]['bbulkSizeTotal'] += size
                bulk[packet[2].stream]['bbulkDuration'] += float(packet[2].time_relative) - bulk[packet[2].stream]['blastBulkTS']
            bulk[packet[2].stream]['blastBulkTS'] = float(packet[2].time_relative)

def detectUpdateSubflows(packet, idle):
    if idle[packet[2].stream]['sfLastPacketTS'] == -1:
        idle[packet[2].stream]['sfLastPacketTS'] = float(packet[2].time_relative)
        idle[packet[2].stream]['sfAcHelper'] = float(packet[2].time_relative)

    if(float(packet[2].time_relative) - idle[packet[2].stream]['sfLastPacketTS']) > 1.0:
        idle[packet[2].stream]['sfCount'] += 1
        updateActiveIdleTime(packet, float(packet[2].time_relative) - idle[packet[2].stream]['sfLastPacketTS'], 5000000)
        idle[packet[2].stream]['sfAcHelper'] = float(packet[2].time_relative)

    idle[packet[2].stream]['sfLastPacketTS'] = float(packet[2].time_relative)

def updateActiveIdleTime(packet, currentTime, threshold):
    if (currentTime - idle[packet[2].stream]['endActiveTime']) * 1000000 > threshold:
        packets[packet[2].stream]['Idle Std'].append(currentTime - idle[packet[2].stream]['endActiveTime'])
        idle[packet[2].stream]['startActiveTime'] = currentTime
        idle[packet[2].stream]['endActiveTime'] = currentTime
    else:
        idle[packet[2].stream]['endActiveTime'] = currentTime

if __name__ == '__main__':

    for packet in cap.sniff_continuously():
        if packet[2].stream in streams:
            continue
        if packet[2].stream not in packets.keys():
            packets[packet[2].stream] = {'Fwd Packet Length Min': [], 'Bwd Packet Length Min': [], 'Flow Bytes/s': 0, \
                                         'Flow Packets/s': 0, 'Bwd IAT Std': [], 'Fwd PSH Flags': 0, 'Bwd PSH Flags': 0, \
                                         'Fwd URG Flags': 0, 'Bwd URG Flags': 0, 'Fwd Packets/s': 0, 'Bwd Packets/s': 0, \
                                         'Min Packet Length': [], 'FIN': 0, 'RST': 0, 'PSH': 0, 'URG': 0, 'Down/Up Ratio': 0, \
                                         'Fwd Avg Bytes/Bulk': 0, 'Fwd Avg Packets/Bulk': 0, 'Fwd Avg Bulk Rate': 0, \
                                         'Bwd Avg Bytes/Bulk': 0, 'Bwd Avg Bulk Rate': 0, 'Init_Win_bytes_backward': 0, \
                                         'min_seg_size_forward': [], 'Idle Std': []}
            src_dst[packet[2].stream] = {packet[1].src: packet[1].dst}
            current_backward_time[packet[2].stream] = 0
            bulk[packet[2].stream] = {'fbulkDuration': 0, 'fbulkPacketCount': 0, 'fbulkSizeTotal': 0, 'fbulkStateCount': 0, \
                                     'fbulkPacketCountHelper': 0, 'fbulkStartHelper': 0, 'fbulkSizeHelper': 0, 'flastBulkTS': 0, \
                                     'bbulkDuration': 0, 'bbulkPacketCount': 0, 'bbulkSizeTotal': 0, 'bbulkStateCount': 0, \
                                     'bbulkPacketCountHelper': 0, 'bbulkStartHelper': 0, 'bbulkSizeHelper': 0, 'blastBulkTS': 0}
            idle[packet[2].stream] = {'sfLastPacketTS': -1, 'sfCount': 0, 'sfAcHelper': -1, 'startActiveTime': 0, 'endActiveTime': 0}

        fwd_bwd(packet, packets)
        flow(packet, packets)

        # Bulk
        updateFlowBulk(packet, src_dst, bulk)

        # Idle Std
        detectUpdateSubflows(packet, idle)

        # Min Packet Length
        packets[packet[2].stream]['Min Packet Length'].append(int(packet[2].len))

        # Flags count
        packets[packet[2].stream]['FIN'] += int(packet[2].flags_fin)
        packets[packet[2].stream]['RST'] += int(packet[2].flags_reset)
        packets[packet[2].stream]['PSH'] += int(packet[2].flags_push)
        packets[packet[2].stream]['URG'] += int(packet[2].flags_urg)

        if packet[2].flags_fin != '0' and packet[2].flags_ack != '0':
            packets[packet[2].stream]['Fwd Packet Length Min'] = min(packets[packet[2].stream]['Fwd Packet Length Min'])
            if len(packets[packet[2].stream]['Bwd Packet Length Min']) != 0:
                packets[packet[2].stream]['Bwd Packet Length Min'] = min(packets[packet[2].stream]['Bwd Packet Length Min'])
            else:
                packets[packet[2].stream]['Bwd Packet Length Min'] = 0

            if float(packet[2].time_relative) != 0:
                packets[packet[2].stream]['Flow Bytes/s'] = packets[packet[2].stream]['Flow Bytes/s'] / float(packet[2].time_relative)
                packets[packet[2].stream]['Flow Packets/s'] = packets[packet[2].stream]['Flow Packets/s'] / float(packet[2].time_relative)

            if len(packets[packet[2].stream]['Bwd IAT Std']) > 2:
                packets[packet[2].stream]['Bwd IAT Std'] = np.std(packets[packet[2].stream]['Bwd IAT Std'][1:], ddof=1)*1000000
            else:
                packets[packet[2].stream]['Bwd IAT Std'] = 0

            packets[packet[2].stream]['Down/Up Ratio'] = round(packets[packet[2].stream]['Bwd Packets/s'] / packets[packet[2].stream]['Fwd Packets/s'])

            if float(packet[2].time_relative) != 0:
                packets[packet[2].stream]['Fwd Packets/s'] = packets[packet[2].stream]['Fwd Packets/s'] / float(packet[2].time_relative)
                packets[packet[2].stream]['Bwd Packets/s'] = packets[packet[2].stream]['Bwd Packets/s'] / float(packet[2].time_relative)

            packets[packet[2].stream]['Min Packet Length'] = min(packets[packet[2].stream]['Min Packet Length'])

            # Bulk
            if bulk[packet[2].stream]['fbulkStateCount'] != 0:
                packets[packet[2].stream]['Fwd Avg Bytes/Bulk'] = bulk[packet[2].stream]['fbulkSizeTotal'] / bulk[packet[2].stream]['fbulkStateCount']

            if bulk[packet[2].stream]['fbulkStateCount'] != 0:
                packets[packet[2].stream]['Fwd Avg Packets/Bulk'] = bulk[packet[2].stream]['fbulkPacketCount'] / bulk[packet[2].stream]['fbulkStateCount']

            if bulk[packet[2].stream]['fbulkDuration'] != 0:
                packets[packet[2].stream]['Fwd Avg Bulk Rate'] = bulk[packet[2].stream]['fbulkSizeTotal'] / bulk[packet[2].stream]['fbulkDuration']

            if bulk[packet[2].stream]['bbulkStateCount'] != 0:
                packets[packet[2].stream]['Bwd Avg Bytes/Bulk'] = bulk[packet[2].stream]['bbulkSizeTotal'] / bulk[packet[2].stream]['bbulkStateCount']

            if bulk[packet[2].stream]['bbulkDuration'] != 0:
                packets[packet[2].stream]['Bwd Avg Bulk Rate'] = bulk[packet[2].stream]['bbulkSizeTotal'] / bulk[packet[2].stream]['bbulkDuration']

            # Init_Win_bytes_backward
            packets[packet[2].stream]['Init_Win_bytes_backward'] += int(packet[2].window_size_value)

            packets[packet[2].stream]['min_seg_size_forward'] = min(packets[packet[2].stream]['min_seg_size_forward'])

            # Idle Std
            if len(packets[packet[2].stream]['Idle Std']) > 1:
                packets[packet[2].stream]['Idle Std'] = np.std(packets[packet[2].stream]['Idle Std'], ddof=1)
            else:
                packets[packet[2].stream]['Idle Std'] = 0

            X = pd.DataFrame([packets[packet[2].stream]], columns=packets[packet[2].stream].keys())
            X = np.array(preprocessing.scale(X))
            prediction = clf.predict(X)
            print(labels[prediction[0]])

            streams.append(packet[2].stream)
            del packets[packet[2].stream]
            del src_dst[packet[2].stream]
            del current_backward_time[packet[2].stream]
            del bulk[packet[2].stream]
            del idle[packet[2].stream]
            if len(streams) >= 1000:
                streams.clear()