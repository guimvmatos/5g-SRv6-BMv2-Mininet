/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*metadata*/
const bit<9> HOST = 1;

/* will be in udp header */
const bit<16> TYPE_IPV6 = 0x86dd;
const bit<8> TYPE_IPV6_2 = 41;
const bit<16> TYPE_GTP = 2152;

/* will be in ipv6 header*/
const bit<8> TYPE_UDP = 17;
const bit<8> TYPE_TCP = 6;
const bit<8> TYPE_SRV6 = 43;

/* lenght of the SIDs list */
#define MAX_HOPS 2

/*list of SIDs to SRv6*/
/*const bit<128> s1 = 2001:0DB8:AC10:FE01:0000:0000:0000:0002;
const bit<128> s2 = 2001:0DB8:AC10:FE01:0000:0000:0000:0001;*/



/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<128> ip6Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv6_t {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    bit<128> src_addr;
    bit<128> dst_addr;
}

header gtp_t {
    bit<3>  version_field_id;
    bit<1>  proto_type_id;
    bit<1>  spare;
    bit<1>  extension_header_flag_id;
    bit<1>  sequence_number_flag_id;
    bit<1>  npdu_number_flag_id;
    bit<8>  msgtype;
    bit<16> msglen;
    bit<32> teid;
}

header udp_t {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> checksum;
}

header srv6_t {
    bit<8> next_hdr;
    bit<8> hdr_ext_len;
    bit<8> routing_type;
    bit<8> segment_left;
    bit<8> last_entry;
    bit<8> flags;
    bit<16> tag;
}

header srv6_list_t {
    ip6Addr_t segment_id;
}   


struct metadata {
    ip6Addr_t next_srv6_sid;
}

struct headers {
    ethernet_t   ethernet;
    ipv6_t       ipv6_outer;
    srv6_t       srv6;
    srv6_list_t[MAX_HOPS]   srv6_list;
    udp_t        udp;
    gtp_t        gtp;
    ipv6_t       ipv6_inner;

}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                /*inout local_metadata_t local_metadata,*/
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV6: parse_ipv6_outer;
            default: accept;
        }
    }

    state parse_ipv6_outer {
        packet.extract(hdr.ipv6_outer);
		transition select(hdr.ipv6_outer.next_hdr){
			TYPE_UDP: parse_udp;
			TYPE_SRV6: parse_srv6;
		}
    }

    state parse_udp {
    	packet.extract(hdr.udp);
    	transition select(hdr.udp.dport){
    		TYPE_GTP: parse_gtp;
            /*default:accetp;*/
    	}
    }

    state parse_gtp {
        packet.extract(hdr.gtp);
        transition accept;
    }

    state parse_srv6{
    	packet.extract(hdr.srv6);
    	transition accept;
    }

    state parse_srv6_list {
        packet.extract(hdr.srv6_list.next);
        bool next_segment = (bit<32>)hdr.srv6.segment_left - 1 == (bit<32>)hdr.srv6_list.lastIndex;
        transition select(next_segment) {
            true: mark_current_srv6;
            _: check_last_srv6;
        }
    }

    state mark_current_srv6 {
        meta.next_srv6_sid = hdr.srv6_list.last.segment_id;
        transition check_last_srv6;
    }

    state check_last_srv6 {
        /* working with bit<8> and int<32> which cannot be cast directly; using bit<32> as common intermediate type for comparision*/
        bool last_segment = (bit<32>)hdr.srv6.last_entry == (bit<32>)hdr.srv6_list.lastIndex;
        transition select(last_segment) {
           true: accept;
           false: parse_srv6_list;
        }
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }
    
    action forward_srv6(macAddr_t dstAddr, egressSpec_t port, ip6Addr_t s0, ip6Addr_t s1){
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;

        /*o certo:fazer a verificacao se o dstAddr == ao destino vinculado ao ip*/
        /*se for o node de destino, fara o decremento, a troca no ipv6 pelo novo sid e o forward*/
        /*como os nos finais nao sao roteadores, vou fazer o seguinte:*/
        /*se eu receber um srv6 de um no final, saberei que ele fez o trabalho dele e esta devolvendo o pacote*/
        /*entao faco o decremento, a troca no ipv6 e o forward*/
        /*como saberei que e um no vindo do no final? se eu receber na porta que esta destinada ao no final*/

        /*conclusao, segundo pesquisas na especificacao da linguagem, e possivel fazer as operacoes desejadas no parser, utilizando*/
        /*os exemplos e codigo nos links do arquivo salvo no desktop*/

        /*if(standard_metadata.ingress_port ==  1){
            hdr.srv6.segment_left = hdr.srv6.segment_left - 1;
            }
        */
        hdr.srv6.segment_left = hdr.srv6.segment_left - 1;
        if (hdr.srv6.segment_left == 1) {
                hdr.ipv6_outer.dst_addr = s1;
            } 
        if (hdr.srv6.segment_left == 0) {
                hdr.ipv6_outer.dst_addr = s0;
            }       
    }

    action drop_srv6(){
        hdr.ipv6_outer.setInvalid();
        hdr.srv6_list[0].setInvalid();
        hdr.srv6_list[1].setInvalid();
    }

    action ipv6_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }

    action build_srv6(ip6Addr_t s1, ip6Addr_t s0) {
        hdr.srv6.setValid();
        hdr.srv6.next_hdr = TYPE_IPV6_2;
        hdr.srv6.hdr_ext_len =  MAX_HOPS * 2;
        hdr.srv6.routing_type = 4;
        hdr.srv6.segment_left = MAX_HOPS -1;
        hdr.srv6.last_entry = MAX_HOPS - 1 ;
        hdr.srv6.flags = 0;
        hdr.srv6.tag = 0;
        hdr.ipv6_outer.next_hdr = TYPE_SRV6;
        hdr.ipv6_outer.dst_addr = s1;
        hdr.ipv6_outer.payload_len = hdr.ipv6_outer.payload_len + 40;
        hdr.srv6_list[0].setValid();
        hdr.srv6_list[0].segment_id = s0;
        hdr.srv6_list[1].setValid();
        hdr.srv6_list[1].segment_id = s1;
        hdr.udp.setInvalid();
        hdr.gtp.setInvalid();
    }



    
    
    table ipv6_outer_lpm {
        key = {
            hdr.ipv6_outer.dst_addr: lpm;
        }
        actions = {
            ipv6_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

/*
        table ipv6_inner_lpm {
        key = {
            hdr.ipv6_inner.dst_addr: lpm;
        }
        actions = {
            ipv6_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
*/
     table srv6_forward_exact{
        key = {
            hdr.ipv6_outer.dst_addr: lpm;
        }
        actions = {
            forward_srv6;
        }
        size = 1024;

    }
   


    table teid_exact{
        key = {
            hdr.gtp.teid: exact;
        }
        actions = {
            build_srv6;
        }
        size = 1024;
    }


    apply{    
        if(hdr.srv6.isValid()){
            /*if(standard_metadata.ingress_port == 1){
                hdr.srv6.segment_left = hdr.srv6.segment_left - 1;

                hdr.ipv6_outer.dst_addr = hdr.srv6_list[0].segment_id;
            }*/

            if(hdr.srv6.segment_left >= 0){
                srv6_forward_exact.apply(); 
                
            }
            
        }

        if (hdr.gtp.isValid()){
            teid_exact.apply();
            hdr.gtp.setInvalid();
            hdr.udp.setInvalid();
            ipv6_outer_lpm.apply();
        } 
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply { }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6_outer);
        packet.emit(hdr.srv6);
        packet.emit(hdr.srv6_list);
        packet.emit(hdr.udp);
        packet.emit(hdr.gtp);
        packet.emit(hdr.ipv6_inner);
        

    }
}	

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;