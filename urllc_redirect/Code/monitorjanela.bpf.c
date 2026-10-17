#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
// janela de 500ms
#define WINDOW_DURATION_NS 500000000ULL

// impporta o modelo gerado pelo emlearn
#include "model500msJANELA.h"

struct flow_metrics
{
    u64 last_packet_ts;
    u64 window_start_ts;
    //count janela atual
    u64 count;
    u64 sum_iat_us;
    u64 sum_sq_iat_us;
    //janela anterior
    s64 prev_mean;
    s64 prev_var;
    // classe travada para o fluxo, decidida uma única vez quando a janela
    // fecha (com estatísticas já assentadas) e reaplicada a todos os pacotes
    // até a próxima janela fechar. evita que o mesmo fluxo TCP alterne entre
    // URLLC/eMBB pacote a pacote, o que causa reordenação e retransmissão.
    s32 sticky_class;
};
// Estrutura do cabeçalho GTP-U

struct gtpu_header {
    u8 flags;
    u8 message_type;
    u16 length;
    u32 teid;
};

#define GTPU_PORT 2152
#define GTPU_CONTROL_PORT 2123

// Estrutura para obter as portas de transporte (TCP/UDP)
struct transport_header_simple {
    u16 source;
    u16 dest;
};

// Estrutura da chave do fluxo
struct flow_key_ts {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
};

// Estrutura do evento
struct ip_event {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    s64 inter_arrival_time_ns;
    u32 tam_packet;
    u8 protocol;
    u32 teid;
    s32 classificacao; // s32 ppra ficar igual o int32_t do modelo
    s64 feat_mean_cur;
    s64 feat_var_cur;
    s64 feat_mean_prev;
    s64 feat_var_prev;
    u64 inference_time_ns;
    // campos do IP externo (túnel GTP-U), usados para correlacionar este
    // evento de classificação com o evento de saída (struct exit_event)
    // emitido quando o pacote efetivamente deixa o host
    u32 outer_src_ip;
    u32 outer_dst_ip;
    u16 outer_ip_id;
};

struct model_context
{
    struct ip_event event;
    int64_t features[4];
    int32_t votes[3];
    u64 inference_start_ts;
    // timestamp de chegada do pacote na interface monitorada (entrada),
    // usado para calcular o tempo de processamento total até a saída
    u64 ingress_ts;
    // offset do IP interno em relação ao início do frame,
    // usado pelo tail call de priorização para reencontrar o pacote
    u32 inner_ip_offset;
    // chave do fluxo sendo classificado, usada ao final da cadeia de
    // tail calls para gravar o resultado em flow_stats->sticky_class
    struct flow_key_ts flow_key;
};

// chave de correlação entre a entrada (XDP) e a saída (TC egress ou
// bpf_redirect) do pacote. 
struct exit_corr_key {
    u32 src_ip;
    u32 dst_ip;
    u16 ip_id;
};

// valor guardado em pending_exit: preserva os identificadores do IP EXTERNO
// (não necessariamente os mesmos da chave que deu match, ver acima) porque é
// isso que o lado Python usa pra correlacionar com a linha de classificação
// original em ip_event/pending_rows.
struct pending_exit_info {
    u64 ingress_ts;
    u32 outer_src_ip;
    u32 outer_dst_ip;
    u16 outer_ip_id;
};

// evento de saída: emitido quando o pacote efetivamente sai do host, seja
// via bpf_redirect (URLLC, no próprio XDP) seja via hook de TC egress
// (eMBB, que segue pela pilha normal de rede/roteamento)
struct exit_event {
    u32 outer_src_ip;
    u32 outer_dst_ip;
    u16 outer_ip_id;
    u64 processing_time_ns;
};

// mapas
BPF_PERF_OUTPUT(events);
BPF_PERF_OUTPUT(exit_events);

// LRU: entradas de pacotes cuja saída nunca é observada (ex: descartados
// pelo roteamento) são naturalmente substituídas em vez de vazar memória
BPF_TABLE("lru_hash", struct exit_corr_key, struct pending_exit_info, pending_exit, 10240);

BPF_HASH(flow_stats, struct flow_key_ts, struct flow_metrics, 10240);

BPF_PROG_ARRAY(prog_array, 10);
BPF_PERCPU_ARRAY(scratchpad, struct model_context, 1);

//priorização ativa do trafego URLLC (XDP_REDIRECT). definida diretamente aqui (e não via #include) porque o BCC so trata como programa BPF "carregável" (visível para load_func) as funções definidas nesse arquivo

struct redirect_config {
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
    u32 ifindex;
};

BPF_ARRAY(redirect_cfg, struct redirect_config, 1);

int prioritize_urllc(struct xdp_md *ctx) {
    int idx = 0;
    struct model_context *ctx_data = scratchpad.lookup(&idx);
    if (!ctx_data) return XDP_PASS;

    struct redirect_config *cfg = redirect_cfg.lookup(&idx);
    if (!cfg) return XDP_PASS;

    u32 inner_ip_offset = ctx_data->inner_ip_offset;

    //limite explícito para o verificador do eBPF: inner_ip_offset vem
    //de um mapa (valor não constante), então precisa de um bound antes de ser usado em aritmética sobre data/data_end
    if (inner_ip_offset < sizeof(struct ethhdr) || inner_ip_offset > 256)
        return XDP_PASS;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + inner_ip_offset + sizeof(struct iphdr) > data_end)
        return XDP_PASS;


    int delta = (int)inner_ip_offset - (int)sizeof(struct ethhdr);
    if (bpf_xdp_adjust_head(ctx, delta))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_PASS;

    __builtin_memcpy(new_eth->h_dest, cfg->dst_mac, ETH_ALEN);
    __builtin_memcpy(new_eth->h_source, cfg->src_mac, ETH_ALEN);
    new_eth->h_proto = htons(ETH_P_IP);

    // ponto de saída real do URLLC: o redirect via XDP_REDIRECT transmite o
    // pacote diretamente pela NIC de destino, sem passar pela pilha normal
    // (e portanto sem passar pelo hook de TC egress), então o tempo de
    // processamento tem que ser fechado e o evento emitido aqui
    struct exit_corr_key corr_key = {};
    corr_key.src_ip = ctx_data->event.outer_src_ip;
    corr_key.dst_ip = ctx_data->event.outer_dst_ip;
    corr_key.ip_id = ctx_data->event.outer_ip_id;
    pending_exit.delete(&corr_key);

    struct exit_event ev = {};
    ev.outer_src_ip = ctx_data->event.outer_src_ip;
    ev.outer_dst_ip = ctx_data->event.outer_dst_ip;
    ev.outer_ip_id = ctx_data->event.outer_ip_id;
    ev.processing_time_ns = bpf_ktime_get_ns() - ctx_data->ingress_ts;
    exit_events.perf_submit(ctx, &ev, sizeof(ev));

    return bpf_redirect(cfg->ifindex, 0);
}

int egress_xdp_enable(struct xdp_md *ctx) {
    return XDP_PASS;
}

int tc_egress_capture(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    struct exit_corr_key corr_key = {};
    corr_key.src_ip = ip->saddr;
    corr_key.dst_ip = ip->daddr;
    corr_key.ip_id = ip->id;

    struct pending_exit_info *info = pending_exit.lookup(&corr_key);
    if (!info)
        return TC_ACT_OK;

    struct exit_event ev = {};
    ev.outer_src_ip = info->outer_src_ip;
    ev.outer_dst_ip = info->outer_dst_ip;
    ev.outer_ip_id = info->outer_ip_id;
    ev.processing_time_ns = bpf_ktime_get_ns() - info->ingress_ts;

    pending_exit.delete(&corr_key);
    exit_events.perf_submit(skb, &ev, sizeof(ev));

    return TC_ACT_OK;
}

#define PROG_TREE_PART1 1
#define PROG_TREE_PART2 2
#define PROG_TREE_PART3 3
#define PROG_PRIORITIZE 4

int monitor_packets(struct xdp_md *ctx) {
    // capturado o mais cedo possível: referência de "entrada na interface"
    // para o cálculo do tempo total de processamento do pacote
    u64 ingress_ts = bpf_ktime_get_ns();

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Cabeçalho Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Apenas pacotes IPv4
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    // Cabeçalho IP externo
    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;

    if (ntohs(outer_ip->frag_off) & 0x3FFF)
        return XDP_PASS;

    if (outer_ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    u8 outer_ihl = outer_ip->ihl;
    if (outer_ihl < 5)
        return XDP_PASS;

    u32 outer_ip_header_len = outer_ihl * 4;

    // Cabeçalho UDP externo
    void *udp_ptr = (void *)outer_ip + outer_ip_header_len;
    if (udp_ptr + sizeof(struct udphdr) > data_end)
        return XDP_PASS;

    struct udphdr *udp = (struct udphdr *)udp_ptr;

    // Apenas pacotes GTP
    if (udp->dest != htons(GTPU_PORT) && udp->dest != htons(GTPU_CONTROL_PORT))
        return XDP_PASS;

    // Cabeçalho GTP
    struct gtpu_header *gtpu = (void *)(udp + 1);
    if ((void *)(gtpu + 1) > data_end)
        return XDP_PASS;


    struct iphdr *inner_ip = NULL;
    //tenta varios tamanhos de cabeçalhos de extensão GTP
    u32 offsets[] = {8, 12, 16, 20, 4};

    #pragma unroll
    for (int i = 0; i < 5; i++) {
        u32 offset = offsets[i];
        void *test_ptr = (void *)gtpu + offset;

        //verifica se o ponteiro + header IP estão dentro dos limites do pacote
        if (test_ptr + sizeof(struct iphdr) > data_end)
            continue;

        struct iphdr *test_ip = (struct iphdr *)test_ptr;

        //validação de que é um header IP
        if (test_ip->version == 4 &&
            test_ip->ihl >= 5 && test_ip->ihl <= 15 &&
            test_ip->tot_len != 0) 
        {
            inner_ip = test_ip;
            break;
        }
    }

    if (inner_ip == NULL)
        return XDP_PASS; 

    //tamanho do cabeçalho IP interno
    u8 inner_ihl = inner_ip->ihl;
    u32 inner_ip_header_len = inner_ihl * 4;
    if ((void *)inner_ip + inner_ip_header_len > data_end)
        return XDP_PASS;

    // Timestamp atual
    u64 current_ktime_ns = bpf_ktime_get_ns();

    // Tamanho do pacote interno (total length do IP interno)
    u32 inner_packet_size = ntohs(inner_ip->tot_len);

    // Cria chave do fluxo
    struct flow_key_ts flow_key = {};
    flow_key.src_ip = inner_ip->saddr;
    flow_key.dst_ip = inner_ip->daddr;
    flow_key.protocol = inner_ip->protocol;
    flow_key.src_port = 0;
    flow_key.dst_port = 0;

    int idx = 0;
    struct model_context *ctx_data = scratchpad.lookup(&idx);
    if (!ctx_data) return XDP_PASS;

    ctx_data->votes[0] = 0; ctx_data->votes[1] = 0; ctx_data->votes[2] = 0;
    ctx_data->inner_ip_offset = (u32)((void *)inner_ip - data);
    ctx_data->ingress_ts = ingress_ts;

    // registra a chegada deste pacote para que o hook de saída (TC egress,
    // caminho normal do eMBB) ou o redirect (caminho rápido do URLLC)
    // consigam calcular o tempo total de processamento até a saída.

    struct pending_exit_info exit_info = {};
    exit_info.ingress_ts = ingress_ts;
    exit_info.outer_src_ip = outer_ip->saddr;
    exit_info.outer_dst_ip = outer_ip->daddr;
    exit_info.outer_ip_id = outer_ip->id;

    struct exit_corr_key outer_key = {};
    outer_key.src_ip = outer_ip->saddr;
    outer_key.dst_ip = outer_ip->daddr;
    outer_key.ip_id = outer_ip->id;
    pending_exit.update(&outer_key, &exit_info);

    struct exit_corr_key inner_key = {};
    inner_key.src_ip = inner_ip->saddr;
    inner_key.dst_ip = inner_ip->daddr;
    inner_key.ip_id = inner_ip->id;
    pending_exit.update(&inner_key, &exit_info);

    // Cria evento
    struct ip_event *evt = &ctx_data->event;
    evt->src_ip = inner_ip->saddr;
    evt->dst_ip = inner_ip->daddr;
    evt->inter_arrival_time_ns = 0;
    evt->tam_packet = inner_packet_size;
    evt->protocol = inner_ip->protocol;
    evt->teid = ntohl(gtpu->teid);
    evt->classificacao = -1;
    evt->src_port = 0;
    evt->dst_port = 0;
    evt->outer_src_ip = outer_ip->saddr;
    evt->outer_dst_ip = outer_ip->daddr;
    evt->outer_ip_id = outer_ip->id;



    //Extrai portas se protocolo for TCP/UDP
    if (inner_ip->protocol == IPPROTO_TCP || inner_ip->protocol == IPPROTO_UDP) {
        void *inner_transport_ptr = (void *)inner_ip + inner_ip_header_len;

        if (inner_transport_ptr + sizeof(struct transport_header_simple) <= data_end) {
            struct transport_header_simple *inner_transport = (struct transport_header_simple *)inner_transport_ptr;
            u16 sport = bpf_ntohs(inner_transport->source);
            u16 dport = bpf_ntohs(inner_transport->dest);
            evt->src_port = bpf_ntohs(inner_transport->source);
            evt->dst_port = bpf_ntohs(inner_transport->dest);
            flow_key.src_port = evt->src_port;
            flow_key.dst_port = evt->dst_port;
        }
    }

    //calc metrica de janela
    struct flow_metrics *metrics = flow_stats.lookup(&flow_key);
    if (!metrics) {
        struct flow_metrics zero = {};
        zero.last_packet_ts = current_ktime_ns;
        zero.window_start_ts = current_ktime_ns;
        // eMBB (sem prioridade) até a primeira janela fechar e produzir uma
        // classificação de verdade — evita redirecionar antes de ter estatística
        zero.sticky_class = 1;
        flow_stats.update(&flow_key, &zero);
        return XDP_PASS;
    }

    s64 iat_ns = (s64)(current_ktime_ns - metrics->last_packet_ts);
    if (iat_ns < 0) iat_ns = 0;

    s64 iat_us = iat_ns / 1000000;
    metrics->last_packet_ts = current_ktime_ns;

    // Verifica Janela (500ms)
    u64 window_age = current_ktime_ns - metrics->window_start_ts;

    u8 window_closed = 0;
    s64 closed_mean = 0;
    s64 closed_var = 0;
    s64 old_prev_mean = metrics->prev_mean;
    s64 old_prev_var = metrics->prev_var;

    if (window_age >= WINDOW_DURATION_NS) {
        // Fecha janela anterior
        if (metrics->count > 0) {
            s64 mean = metrics->sum_iat_us / metrics->count;
            s64 mean_sq = mean * mean;
            s64 avg_sq = metrics->sum_sq_iat_us / metrics->count;

            closed_mean = mean;
            closed_var = avg_sq - mean_sq;
        } else {
            closed_mean = 0;
            closed_var = 0;
        }
        metrics->prev_mean = closed_mean;
        metrics->prev_var = closed_var;

        // reset
        metrics->window_start_ts = current_ktime_ns;
        metrics->count = 0;
        metrics->sum_iat_us = 0;
        metrics->sum_sq_iat_us = 0;
        window_closed = 1;
    }

    // atualiza janela atual
    metrics->count++;
    metrics->sum_iat_us += iat_us;
    metrics->sum_sq_iat_us += (iat_us * iat_us);

    s64 cur_mean = 0;
    s64 cur_var = 0;

    if (metrics->count > 0) {
        cur_mean = metrics->sum_iat_us / metrics->count;
        s64 mean_sq = cur_mean * cur_mean;
        s64 avg_sq = metrics->sum_sq_iat_us / metrics->count;
        cur_var = avg_sq - mean_sq;
    }

    evt->inter_arrival_time_ns = iat_ns;
    evt->feat_mean_cur = cur_mean;
    evt->feat_var_cur = cur_var;
    evt->feat_mean_prev = metrics->prev_mean;
    evt->feat_var_prev = metrics->prev_var;

    if (!window_closed) {
        evt->classificacao = metrics->sticky_class;
        evt->inference_time_ns = 0;
        events.perf_submit(ctx, evt, sizeof(struct ip_event));

        if (metrics->sticky_class == 0) {
            prog_array.call(ctx, PROG_PRIORITIZE);
        }
        return XDP_PASS;
    }

    // janela acabou de fechar: reclassifica com as estatísticas já
    // assentadas da janela que fechou (closed_mean/var) e da janela anterior
    // a essa (old_prev_mean/var), em vez das médias/variâncias ainda em
    // formação da janela nova que está começando agora
    ctx_data->features[0] = closed_mean;
    ctx_data->features[1] = closed_var;
    ctx_data->features[2] = old_prev_mean;
    ctx_data->features[3] = old_prev_var;
    ctx_data->flow_key = flow_key;

    ctx_data->inference_start_ts = bpf_ktime_get_ns();

    //tailcall para class 1
    prog_array.call(ctx, PROG_TREE_PART1);
    return XDP_PASS;
}


//prog 2 arv 0-3
int run_trees_part1(struct xdp_md *ctx) {
    int idx = 0;
    struct model_context *ctx_data = scratchpad.lookup(&idx);
    if (!ctx_data) return XDP_PASS;

    int64_t *f = ctx_data->features;

    int c;
    c = model_tree_0(f, 4); ctx_data->votes[c]++;
    c = model_tree_1(f, 4); ctx_data->votes[c]++;
    c = model_tree_2(f, 4); ctx_data->votes[c]++;
    c = model_tree_3(f, 4); ctx_data->votes[c]++;
    prog_array.call(ctx, PROG_TREE_PART2);
    return XDP_PASS;
}
//prog 3 arv 4-6
int run_trees_part2(struct xdp_md *ctx) {
    int idx = 0;
    struct model_context *ctx_data = scratchpad.lookup(&idx);
    if (!ctx_data) return XDP_PASS;
    int64_t *f = ctx_data->features;

    int c;
    c = model_tree_4(f, 4); ctx_data->votes[c]++;
    c = model_tree_5(f, 4); ctx_data->votes[c]++;
    c = model_tree_6(f, 4); ctx_data->votes[c]++;

    prog_array.call(ctx, PROG_TREE_PART3);
    return XDP_PASS;
}
int run_trees_part3(struct xdp_md *ctx){
    int idx = 0;
    struct model_context *ctx_data = scratchpad.lookup(&idx);
    if (!ctx_data) return XDP_PASS;
    int64_t *f = ctx_data->features;
    
    int c;
    c = model_tree_7(f, 4); ctx_data->votes[c]++;
    c = model_tree_8(f, 4); ctx_data->votes[c]++;
    c = model_tree_9(f, 4); ctx_data->votes[c]++;

    int32_t most_voted_class = -1;
    int32_t most_voted_votes = -1;


    #pragma unroll
    for (int i = 0; i < 3; i++) {
        if (ctx_data->votes[i] > most_voted_votes) {
            most_voted_class = i;
            most_voted_votes = ctx_data->votes[i];
        }
    }

    u64 now = bpf_ktime_get_ns();
    ctx_data->event.inference_time_ns = now - ctx_data->inference_start_ts;

    ctx_data->event.classificacao = most_voted_class;
    events.perf_submit(ctx, &ctx_data->event, sizeof(struct ip_event));

    // trava essa classe para o fluxo até a próxima janela fechar, para que
    // os demais pacotes da janela (tratados no caminho rápido de
    // monitor_packets, sem passar pelas árvores) sigam a mesma decisão
    struct flow_metrics *metrics = flow_stats.lookup(&ctx_data->flow_key);
    if (metrics)
        metrics->sticky_class = most_voted_class;

    // classe 0 = URLLC: prioriza encaminhando direto pelo XDP
    if (most_voted_class == 0) {
        prog_array.call(ctx, PROG_PRIORITIZE);
    }
    return XDP_PASS;
}