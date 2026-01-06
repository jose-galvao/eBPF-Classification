#!/usr/bin/env python3

import socket
import struct
from bcc import BPF
import ctypes as ct

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
        ("classificacao", ct.c_int32),
        ('feat_mean_cur', ct.c_int64),
        ('feat_var_cur', ct.c_int64),
        ('feat_mean_prev', ct.c_int64),
        ('feat_var_prev', ct.c_int64),
        ('inference_time_ns', ct.c_uint64),
    ]

Clas_mapa = {
    0: 'URLLC',
    1: 'eMBB',
    -1: 'S/C',
}

def ip_to_str(ip_int):
    return socket.inet_ntoa(struct.pack("I", ip_int))

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(IpEvent)).contents

    src_ip_str = ip_to_str(event.src_ip)
    dst_ip_str = ip_to_str(event.dst_ip)
    src_port_h = event.src_port
    dst_port_h = event.dst_port

    # formata o IAT para exibição
    iat_str = "NaN"
    if event.inter_arrival_time_ns > 0:
        iat_ms = event.inter_arrival_time_ns / 1000
        iat_str = f"{iat_ms:.3f}"
    elif event.inter_arrival_time_ns == 0:
        iat_str = 0
    
    classifica_int = event.classificacao
    classifica_str = Clas_mapa.get(classifica_int, str(classifica_int))

    inference_us = event.inference_time_ns / 1000.0
    inf_time_str = f"{inference_us:.3f}"

    print(f"{iat_str};{src_ip_str};{src_port_h};{dst_ip_str};{dst_port_h};{event.tam_packet};{event.protocol};{classifica_str};{event.feat_mean_cur};{event.feat_var_cur};{event.feat_mean_prev};{event.feat_var_prev};{inf_time_str}")


def main():
    interface_monitorada = "enp0s8"

    bpf_instance = None
    try:
        bpf_instance = BPF(src_file='monitorjanela.bpf.c')
        monitor_fn = bpf_instance.load_func("monitor_packets", BPF.XDP)

        prog_tree1 = bpf_instance.load_func("run_trees_part1", BPF.XDP)
        prog_tree2 = bpf_instance.load_func("run_trees_part2", BPF.XDP)
        prog_tree3 = bpf_instance.load_func("run_trees_part3", BPF.XDP)

        prog_array = bpf_instance.get_table("prog_array")
        prog_array[ct.c_int(1)] = ct.c_int(prog_tree1.fd)
        prog_array[ct.c_int(2)] = ct.c_int(prog_tree2.fd)
        prog_array[ct.c_int(3)] = ct.c_int(prog_tree3.fd)
        try:
            bpf_instance.remove_xdp(interface_monitorada, 0)
        except Exception:
            pass

        bpf_instance.attach_xdp(interface_monitorada, monitor_fn, 0)
        bpf_instance["events"].open_perf_buffer(print_event)

        # cabeçalho de saída
        header = f"{'IAT_(ms)'};{'SRC_IP'};{'SRC_PORT'};{'DST_IP'};{'DST_PORT'};{'PACKET_SIZE_(B)'};{'PROTO'};{'CLASS'};{'MED_AT'};{'VAR_AT'};{'MED_PAST'};{'VAR_PAST'};{'INF_US'}"
        print(header)

        while True:
            try:
                bpf_instance.perf_buffer_poll(timeout=200)
            except KeyboardInterrupt:
                break

    finally:
        if bpf_instance:
            try:
                bpf_instance.remove_xdp(interface_monitorada, 0)
            except Exception:
                pass

if __name__ == "__main__":
    main()