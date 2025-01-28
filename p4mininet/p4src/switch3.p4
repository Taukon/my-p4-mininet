/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV6 = 0x86dd;

const bit<8>  INT_PROTOCOL = 0xFD;
const bit<8>  TRACE_PROTOCOL = 0xFE;

// #define MAX_HOPS 10
#define MAX_HOPS 9

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

typedef bit<128> switchID_t;
// typedef bit<32> switchID_t;
// typedef bit<32> qdepth_t;
// typedef bit<32> qlatency_t;
// typedef bit<32> plength_t;
// typedef bit<32> txtotal_t;

#define SWTRACE_SIZE 16
// #define SWTRACE_SIZE 4

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
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

header mri_t {
    bit<16>  count;
}

header switch_t {
    switchID_t  swid;
    // qdepth_t    qdepth;
    // qlatency_t  qlatency;
    // plength_t   plength;
    // txtotal_t   txtotal;
}

struct ingress_metadata_t {
    bit<16>  count;
}

struct parser_metadata_t {
    bit<16>  remaining;
}

struct clone_mri_metadata_t {
    bit<1>  is_clone;
    bit<1>  is_loop;
}

struct swtrace_metadata_t {
    bit<1>  is_set;
    bit<1>  is_over;
    switchID_t swid;
}

struct frr_metadata_t {
    bit<1>  is_frr_port;
    bit<1>  to_frr_port;
}

struct metadata {
    bit<16> l4Len;
    ingress_metadata_t   ingress_metadata;
    parser_metadata_t   parser_metadata;
    clone_mri_metadata_t clone_mri_metadata;
    swtrace_metadata_t   swtrace_metadata;
    frr_metadata_t      frr_metadata;
}

struct headers {
    ethernet_t           ethernet;
    ipv4_t               ipv4;
    ipv6_t               ipv6;
    mri_t                mri;
    switch_t             over_swtrace;
    switch_t[MAX_HOPS]   swtraces;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV6: parse_ipv6;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_hdr) {
            INT_PROTOCOL: parse_mri;
            TRACE_PROTOCOL: parse_mri;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            // INT_PROTOCOL: parse_mri;
            // TRACE_PROTOCOL: parse_mri;
            default: accept;
        }
    }
 
   state parse_mri {
        packet.extract(hdr.mri);
        meta.parser_metadata.remaining = hdr.mri.count;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default: parse_swtrace;
        }
    }

    state parse_swtrace {
        packet.extract(hdr.swtraces.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining  - 1;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default: parse_swtrace;
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
        mark_to_drop(standard_metadata);
    }

    // ---------------------------for FRR action & table----------------------------

    action forward_from_frr(egressSpec_t port) {
        meta.frr_metadata.is_frr_port = 1;
        meta.frr_metadata.to_frr_port = 0;
        standard_metadata.egress_spec = port;
    }

    action frr_forward_no_action() {
        meta.frr_metadata.is_frr_port = 0;
        meta.frr_metadata.to_frr_port = 0;
    }
    
    // table_entry['MyIngress.from_frr_table'].read(function=lambda x: print(x))
    table from_frr_table {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            forward_from_frr;
            frr_forward_no_action;
        }
        size = 256;
        default_action = frr_forward_no_action();
    }


    action forward_to_frr(egressSpec_t port) {
        meta.frr_metadata.to_frr_port = 1;
        standard_metadata.egress_spec = port;
    }

    table to_frr_table {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            forward_to_frr;
            NoAction;
        }
        size = 256;
        default_action = NoAction();
    }

    
    // ---------------------------mri action & table----------------------------

    action mri_clone_no_action() {
        meta.clone_mri_metadata.is_clone = 0;
    }

    action mri_clone(bit<16> mcast_grp_id) {
        meta.clone_mri_metadata.is_clone = 1;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        standard_metadata.mcast_grp = mcast_grp_id;
    }

    table mri_clone_table {
        // key = {
        //     standard_metadata.ingress_port: exact;
        // }
        actions = {
            mri_clone;
            mri_clone_no_action;
        }
        default_action = mri_clone_no_action();
    }

    action mri_loop_no_action() {
        meta.clone_mri_metadata.is_loop = 0;
    }

    action mri_is_loop(switchID_t swid) {
        meta.clone_mri_metadata.is_loop = 0;
        bit<16> tmp_count = hdr.mri.count;

        // MAX_HOPS = 9
        if (tmp_count == 9){
            if(hdr.swtraces[tmp_count - 1].swid == swid){
                meta.clone_mri_metadata.is_loop = 1;
            }
            tmp_count = tmp_count - 1;
        }
        
        if (tmp_count == 8){
            if(hdr.swtraces[tmp_count - 1].swid == swid){
                meta.clone_mri_metadata.is_loop = 1;
            }
            tmp_count = tmp_count - 1;
        }

        if (tmp_count == 7){
            if(hdr.swtraces[tmp_count - 1].swid == swid){
                meta.clone_mri_metadata.is_loop = 1;
            }
            tmp_count = tmp_count - 1;
        }

        if (tmp_count == 6){
            if(hdr.swtraces[tmp_count - 1].swid == swid){
                meta.clone_mri_metadata.is_loop = 1;
            }
            tmp_count = tmp_count - 1;
        }

        if (tmp_count == 5){
            if(hdr.swtraces[tmp_count - 1].swid == swid){
                meta.clone_mri_metadata.is_loop = 1;
            }
            tmp_count = tmp_count - 1;
        }

        if (tmp_count == 4){
            if(hdr.swtraces[tmp_count - 1].swid == swid){
                meta.clone_mri_metadata.is_loop = 1;
            }
            tmp_count = tmp_count - 1;
        }

        if (tmp_count == 3){
            if(hdr.swtraces[tmp_count - 1].swid == swid){
                meta.clone_mri_metadata.is_loop = 1;
            }
            tmp_count = tmp_count - 1;
        }

        if (tmp_count == 2){
            if(hdr.swtraces[tmp_count - 1].swid == swid){
                meta.clone_mri_metadata.is_loop = 1;
            }
            tmp_count = tmp_count - 1;
        }

        if (tmp_count == 1){
            if(hdr.swtraces[tmp_count - 1].swid == swid){
                meta.clone_mri_metadata.is_loop = 1;
            }
        }
    }

    table mri_is_loop_table {
        actions = {
            mri_is_loop;
            mri_loop_no_action; 
        }
        default_action = mri_loop_no_action();
    }


    apply {
        // from dummy frr port
        from_frr_table.apply();
        if(meta.frr_metadata.is_frr_port == 1) {
            return;
        }

        // --------------------Multi-Hop Route Inspection--------------------
        if(hdr.mri.isValid() && hdr.ipv6.isValid() && hdr.ipv6.next_hdr == INT_PROTOCOL){
            if(hdr.ipv6.hop_limit > 0){
                hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
            }else{
                drop();
                return;
            }

            mri_is_loop_table.apply();

            if(meta.clone_mri_metadata.is_loop == 0 && hdr.mri.count < MAX_HOPS){
                mri_clone_table.apply(); 
                return;
            }

            // drop();
            return;
        }

        // --------------------For TRACE OSPF Route--------------------
        if(hdr.mri.isValid() && hdr.ipv6.isValid() && hdr.ipv6.next_hdr == TRACE_PROTOCOL){
            meta.clone_mri_metadata.is_loop = 0;
            meta.clone_mri_metadata.is_clone = 0;
        }

        // ------------------------------------------------------------------

        to_frr_table.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }


    // ---------------------------mri action & table----------------------------

    action src_mac_rewrite(macAddr_t srcAddr) {
        hdr.ethernet.srcAddr = srcAddr;
    }

    table mri_mac_table {
        key = {
            standard_metadata.egress_port : exact;
        }
        actions = {
            src_mac_rewrite;
            // NoAction;
            drop;
        }
        // default_action =  NoAction;
        default_action = drop;
    }

    action swtrace_no_action() {
        meta.swtrace_metadata.is_set = 0;
    }

    action add_swtrace(switchID_t swid) { 
        meta.swtrace_metadata.swid = swid;
        meta.swtrace_metadata.is_set = 1;

        hdr.mri.count = hdr.mri.count + 1;
        if (hdr.mri.count > MAX_HOPS){
            meta.swtrace_metadata.is_over = 1;
        }else{
            meta.swtrace_metadata.is_over = 0;
        }
        
        // hdr.swtraces.push_front(1);
        // hdr.swtraces[0].setValid();
        // hdr.swtraces[0].swid = swid;
 
	    // hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + SWTRACE_SIZE;
    }

    table swtrace_table {
        actions = { 
	        add_swtrace; 
	        swtrace_no_action;
        }
        default_action = swtrace_no_action(); 
    }

    apply {

        // When is the case to use frr, return.
        if(meta.frr_metadata.is_frr_port == 1 || meta.frr_metadata.to_frr_port == 1) {
            if(meta.frr_metadata.is_frr_port == 0 && hdr.mri.isValid()){
                
            }else{
                return;
            }
        }
        
        // --------------------Multi-Hop Route Inspection--------------------
        
        // Prune multicast packet to ingress port to preventing loop
        if (meta.clone_mri_metadata.is_clone == 1 && standard_metadata.egress_port == standard_metadata.ingress_port){
            drop();
        }else{

            if (hdr.mri.isValid()) {
                swtrace_table.apply();
                if(meta.swtrace_metadata.is_set == 1 && meta.swtrace_metadata.is_over == 1){
                    hdr.over_swtrace.setValid();
                    hdr.over_swtrace.swid = meta.swtrace_metadata.swid;
        
                }else if(meta.swtrace_metadata.is_set == 1 && meta.swtrace_metadata.is_over == 0){
                    hdr.swtraces.push_front(1);
                    hdr.swtraces[0].setValid();
                    hdr.swtraces[0].swid = meta.swtrace_metadata.swid;
                }

                if(meta.clone_mri_metadata.is_clone == 1){
                    mri_mac_table.apply();
                }
            }

            if (hdr.ipv4.isValid()) {
                meta.l4Len = hdr.ipv4.totalLen - (bit<16>)(hdr.ipv4.ihl)*4;
            }
            
        }

        // ------------------------------------------------------------------
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	    update_checksum(
	        hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr 
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.mri);
        packet.emit(hdr.over_swtrace);
        packet.emit(hdr.swtraces);                 
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
