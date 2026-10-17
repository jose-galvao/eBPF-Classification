#!/usr/bin/env python3

import socket
import struct
import subprocess
import time
from bcc import BPF
from pyroute2 import IPRoute
import ctypes as ct

#interface de saída para onde o tráfego URLLC é redirecionado via XDP_REDIRECT.
#também é a interface de uplink por onde o eMBB sai após seguir o caminho
#normal de roteamento do kernel (por isso é nela que o hook de TC egress,
#usado para medir o tempo de processamento do eMBB, é anexado).
INTERFACE_SAIDA_URLLC = "enp10s0"

# host de destino do tráfego URLLC redirecionado (pacote interno já sem o
# encapsulamento GTP-U). está no mesmo segmento L2 de INTERFACE_SAIDA_URLLC
# (rota "scope link", sem gateway), então o MAC de destino do frame precisa
# ser o MAC dessa própria VM, resolvido via ARP.
IP_DESTINO_URLLC = "192.168.40.20"

# tempo máximo (s) que um pacote classificado fica esperando pelo evento de
# saída antes de ser impresso com tempo de processamento marcado como NaN
# (ex: pacote descartado em algum ponto entre a classificação e a saída)
PENDING_EXIT_TIMEOUT_S = 3.0

class RedirectConfig(ct.Structure):
    _fields_ = [
        ("src_mac", ct.c_uint8 * 6),
        ("dst_mac", ct.c_uint8 * 6),
        ("ifindex", ct.c_uint32)
    ]


def mac_str_to_bytes(mac_str):
    return (ct.c_uint8 * 6)(*[int(b, 16) for b in mac_str.split(":")])


def resolver_mac_destino(ipr, ifindex, ip_destino, tentativas=5, intervalo_s=0.5):
    for _ in range(tentativas):
        for neigh in ipr.get_neighbours(dst=ip_destino, ifindex=ifindex):
            lladdr = dict(neigh['attrs']).get('NDA_LLADDR')
            if lladdr:
                return lladdr
        # host ainda não está na tabela ARP: força a resolução com um ping
        subprocess.run(["ping", "-c", "1", "-W", "1", ip_destino],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(intervalo_s)
    raise RuntimeError(f"não foi possível resolver o MAC de {ip_destino} via ARP")


def ler_mac_interface(ifname):
    with open(f"/sys/class/net/{ifname}/address") as f:
        return f.read().strip()

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
        ('outer_src_ip', ct.c_uint32),
        ('outer_dst_ip', ct.c_uint32),
        ('outer_ip_id', ct.c_uint16),
    ]

# emitido quando o pacote efetivamente sai do host: pelo bpf_redirect (URLLC)
# ou pelo hook de TC egress (eMBB, que segue o caminho normal do kernel)
class ExitEvent(ct.Structure):
    _fields_ = [
        ("outer_src_ip", ct.c_uint32),
        ("outer_dst_ip", ct.c_uint32),
        ("outer_ip_id", ct.c_uint16),
        ("processing_time_ns", ct.c_uint64),
    ]

Clas_mapa = {
    0: 'URLLC',
    1: 'eMBB',
    -1: 'S/C',
}

def ip_to_str(ip_int):
    return socket.inet_ntoa(struct.pack("I", ip_int))

# linhas já classificadas aguardando o evento de saída correspondente, para
# poder imprimir o tempo total de processamento (entrada -> saída) na mesma
# linha. chave: (outer_src_ip, outer_dst_ip, outer_ip_id)
pending_rows = {}

# evento de saída que chegou ANTES da classificação correspondente. isso é
# comum no caminho URLLC, onde os dois eventos são emitidos quase juntos
# (dentro da mesma execução do XDP) e a ordem de entrega entre dois perf
# buffers distintos não é garantida. guarda aqui até a classificação chegar,
# em vez de descartar, se não a linha nunca casa e sempre vira NaN.
pending_exits = {}

def corr_key_from(outer_src_ip, outer_dst_ip, outer_ip_id):
    return (outer_src_ip, outer_dst_ip, outer_ip_id)

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(IpEvent)).contents

    src_ip_str = ip_to_str(event.src_ip)
    dst_ip_str = ip_to_str(event.dst_ip)
    src_port_h = event.src_port
    dst_port_h = event.dst_port

    #formata o IAT para exibição
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

    row = f"{iat_str};{src_ip_str};{src_port_h};{dst_ip_str};{dst_port_h};{event.tam_packet};{event.protocol};{classifica_str};{event.feat_mean_cur};{event.feat_var_cur};{event.feat_mean_prev};{event.feat_var_prev};{inf_time_str}"

    key = corr_key_from(event.outer_src_ip, event.outer_dst_ip, event.outer_ip_id)

    exit_entry = pending_exits.pop(key, None)
    if exit_entry is not None:
        # o evento de saída já tinha chegado antes (comum no URLLC)
        proc_us, _ = exit_entry
        print(f"{row};{proc_us:.3f}")
        return

    pending_rows[key] = (row, time.monotonic())


def print_exit_event(cpu, data, size):
    ev = ct.cast(data, ct.POINTER(ExitEvent)).contents
    key = corr_key_from(ev.outer_src_ip, ev.outer_dst_ip, ev.outer_ip_id)

    proc_us = ev.processing_time_ns / 1000.0

    entry = pending_rows.pop(key, None)
    if entry is None:
        # evento de saída chegou antes do evento de classificação
        # (reordenação entre os dois perf buffers, comum no URLLC) — guarda
        # pra quando a classificação chegar, em vez de descartar
        pending_exits[key] = (proc_us, time.monotonic())
        return

    row, _ = entry
    print(f"{row};{proc_us:.3f}")


def flush_stale_rows():
    now = time.monotonic()

    stale_keys = [k for k, (_, ts) in pending_rows.items() if now - ts > PENDING_EXIT_TIMEOUT_S]
    for k in stale_keys:
        row, _ = pending_rows.pop(k)
        print(f"{row};NaN")

    stale_exit_keys = [k for k, (_, ts) in pending_exits.items() if now - ts > PENDING_EXIT_TIMEOUT_S]
    for k in stale_exit_keys:
        pending_exits.pop(k)


def main():
    interface_monitorada = "enp9s0"

    bpf_instance = None
    ipr = None
    tc_out_idx = None
    clsact_added = False
    try:
        bpf_instance = BPF(src_file='monitorjanela.bpf.c')
        monitor_fn = bpf_instance.load_func("monitor_packets", BPF.XDP)

        prog_tree1 = bpf_instance.load_func("run_trees_part1", BPF.XDP)
        prog_tree2 = bpf_instance.load_func("run_trees_part2", BPF.XDP)
        prog_tree3 = bpf_instance.load_func("run_trees_part3", BPF.XDP)
        prog_priorizacao = bpf_instance.load_func("prioritize_urllc", BPF.XDP)
        tc_egress_fn = bpf_instance.load_func("tc_egress_capture", BPF.SCHED_CLS)
        egress_xdp_fn = bpf_instance.load_func("egress_xdp_enable", BPF.XDP)

        prog_array = bpf_instance.get_table("prog_array")
        prog_array[ct.c_int(1)] = ct.c_int(prog_tree1.fd)
        prog_array[ct.c_int(2)] = ct.c_int(prog_tree2.fd)
        prog_array[ct.c_int(3)] = ct.c_int(prog_tree3.fd)
        prog_array[ct.c_int(4)] = ct.c_int(prog_priorizacao.fd)

        ipr = IPRoute()

        redirect_cfg = bpf_instance.get_table("redirect_cfg")
        cfg = RedirectConfig()
        cfg.src_mac = mac_str_to_bytes(ler_mac_interface(INTERFACE_SAIDA_URLLC))
        cfg.ifindex = socket.if_nametoindex(INTERFACE_SAIDA_URLLC)
        dst_mac_str = resolver_mac_destino(ipr, cfg.ifindex, IP_DESTINO_URLLC)
        cfg.dst_mac = mac_str_to_bytes(dst_mac_str)
        redirect_cfg[ct.c_int(0)] = cfg

        try:
            bpf_instance.remove_xdp(interface_monitorada, 0)
        except Exception:
            pass

        bpf_instance.attach_xdp(interface_monitorada, monitor_fn, 0)

        #sem isso todo redirect pra cá falha com ENXIO, sem
        # nenhum aviso visível no eBPF (só aparece no tracepoint
        # xdp:xdp_redirect_err do kernel). esse attach só "liga" o XDP em
        # enp10s0, não filtra nada (sempre XDP_PASS).
        try:
            bpf_instance.remove_xdp(INTERFACE_SAIDA_URLLC, 0)
        except Exception:
            pass
        bpf_instance.attach_xdp(INTERFACE_SAIDA_URLLC, egress_xdp_fn, 0)

        # hook de TC egress na interface de uplink, para capturar o instante
        # de saída real do eMBB (que segue o caminho normal do kernel após o
        # XDP_PASS, ao contrário do URLLC que é redirecionado direto no XDP)
        tc_out_idx = cfg.ifindex
        try:
            ipr.tc("add", "clsact", tc_out_idx)
            clsact_added = True
        except Exception:
            pass  # clsact já existente (ex: execução anterior não finalizada)
        ipr.tc("add-filter", "bpf", tc_out_idx, ":1", fd=tc_egress_fn.fd,
               name=tc_egress_fn.name, parent="ffff:fff3", classid=1,
               direct_action=True)

        bpf_instance["events"].open_perf_buffer(print_event)
        bpf_instance["exit_events"].open_perf_buffer(print_exit_event)

        # cabeçalho de saída
        header = f"{'IAT_(ms)'};{'SRC_IP'};{'SRC_PORT'};{'DST_IP'};{'DST_PORT'};{'PACKET_SIZE_(B)'};{'PROTO'};{'CLASS'};{'MED_AT'};{'VAR_AT'};{'MED_PAST'};{'VAR_PAST'};{'INF_US'};{'PROC_US'}"
        print(header)

        while True:
            try:
                bpf_instance.perf_buffer_poll(timeout=200)
                flush_stale_rows()
            except KeyboardInterrupt:
                break

    finally:
        if bpf_instance:
            try:
                bpf_instance.remove_xdp(interface_monitorada, 0)
            except Exception:
                pass
            try:
                bpf_instance.remove_xdp(INTERFACE_SAIDA_URLLC, 0)
            except Exception:
                pass
        if ipr and tc_out_idx is not None and clsact_added:
            try:
                ipr.tc("del", "clsact", tc_out_idx)
            except Exception:
                pass
        if ipr:
            ipr.close()

if __name__ == "__main__":
    main()
