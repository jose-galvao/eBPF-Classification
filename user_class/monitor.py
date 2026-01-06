#!/usr/bin/env python3

import socket
import struct
from bcc import BPF
import ctypes as ct
import os
import sys
import time
from collections import defaultdict

#biblioteca compartilhada
LIB_PATH = "./libclassifier.so"

if not os.path.exists(LIB_PATH):
    print(f"Biblioteca não encontrada", file=sys.stderr)
    sys.exit(1)

classifier_lib = ct.CDLL(LIB_PATH)
#define argumentos (4 floats) e retorno (int32)
classifier_lib.predict_wrapper.argtypes = [ct.c_float, ct.c_float, ct.c_float, ct.c_float]
classifier_lib.predict_wrapper.restype = ct.c_int32

class IpEvent(ct.Structure):
    _fields_ = [
        ("src_ip", ct.c_uint32),
        ("dst_ip", ct.c_uint32),
        ("src_port", ct.c_uint16),
        ("dst_port", ct.c_uint16),
        ("inter_arrival_time_ns", ct.c_int64),
        ("tam_packet", ct.c_uint32),
        ("protocol", ct.c_uint8),
        ("teid", ct.c_uint32),
        ("classificacao", ct.c_int32) 
    ]

Clas_mapa = { 0: 'URLLC', 1: 'eMBB', -1: 'S/C' }

def ip_to_str(ip_int):
    return socket.inet_ntoa(struct.pack("I", ip_int))

# gerenciamento de estado
class FlowState:
    def __init__(self):
        self.iats = []           
        self.window_start = 0    
        self.prev_mean = 0.0
        self.prev_var = 0.0

flows = defaultdict(FlowState)
WINDOW_MS = 500 # 500ms

# função de classificação
def classify_flow(flow, key, is_partial=False):
    count = len(flow.iats)
    if count == 0:
        return
    
    t_start = time.perf_counter_ns()


    cur_mean = sum(flow.iats) / count
    cur_var = 0.0
    if count > 1:
        cur_var = sum((x - cur_mean) ** 2 for x in flow.iats) / count
    
    try:
        class_id = classifier_lib.predict_wrapper(
            ct.c_float(cur_mean),
            ct.c_float(cur_var),
            ct.c_float(flow.prev_mean),
            ct.c_float(flow.prev_var)
        )

        t_end = time.perf_counter_ns()
        

        inferencia_us = (t_end - t_start) / 1000
        
        class_str = Clas_mapa.get(class_id, str(class_id))
        src = ip_to_str(key[0])
        dst = ip_to_str(key[1])

        print(f"{src};{key[2]};{dst};{key[3]};{key[4]};"
              f"{class_str};{count};{cur_mean:.4f};{cur_var:.4f};"
              f"{flow.prev_mean:.4f};{flow.prev_var:.4f};{inferencia_us:.3f}")

    except Exception as e:
        print(f"Erro Classificacao: {e}", file=sys.stderr)

    flow.prev_mean = cur_mean
    flow.prev_var = cur_var
    flow.iats = []

def process_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(IpEvent)).contents
    
    if event.inter_arrival_time_ns <= 0:
        return

    iat_ms = event.inter_arrival_time_ns / 1000000
    
    key = (event.src_ip, event.dst_ip, event.src_port, event.dst_port, event.protocol)
    flow = flows[key]
    
    now_ms = time.time() * 1000

    if flow.window_start == 0:
        flow.window_start = now_ms

    # verifica a janela
    if (now_ms - flow.window_start) >= WINDOW_MS:
        classify_flow(flow, key, is_partial=False)
        flow.window_start = now_ms 

    flow.iats.append(iat_ms)

def main():
    interface = "enp0s8"

    b = BPF(src_file="monitor.bpf.c")
    fn = b.load_func("monitor_packets", BPF.XDP)
    
    try:
        b.remove_xdp(interface, 0)
    except:
        pass

    def print_lost(count):
        print(f"Perda de {count} eventos do buffer (aumentar o buffer)", file=sys.stderr)
        
    b.attach_xdp(interface, fn, 0)
    b["events"].open_perf_buffer(process_event, page_cnt=2048, lost_cb=print_lost)
    #b["events"].open_perf_buffer(process_event)
    
    print("SRC_IP;SRC_PORT;DST_IP;DST_PORT;PROTO;CLASS;PACKET_COUNT;MEAN_IAT_MS;VAR_IAT_MS;PREV_MEAN_MS;PREV_VAR_MS;INF_US")
    
    try:
        while True:
            b.perf_buffer_poll(timeout=100)
            
            now_ms = time.time() * 1000
            for key in list(flows.keys()):
                flow = flows[key]
                if (now_ms - flow.window_start) >= WINDOW_MS and len(flow.iats) > 0:
                    classify_flow(flow, key, is_partial=False)
                    flow.window_start = now_ms

    except KeyboardInterrupt:
        # saida com classificação final
        for key, flow in flows.items():
            if len(flow.iats) > 0:
                classify_flow(flow, key, is_partial=True)
                
    finally:
        try:
            b.remove_xdp(interface, 0)
            print("XDP removido.", file=sys.stderr)
        except:
            pass

if __name__ == "__main__":
    main()
