/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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

struct ingress_metadata_t {
    bit<16>  count;
}

struct parser_metadata_t {
    bit<16>  remaining;
}

struct frr_metadata_t {
    bit<1>  is_frr_port;
    bit<1>  to_frr_port;
}

struct metadata {
    ingress_metadata_t   ingress_metadata;
    parser_metadata_t   parser_metadata;
    frr_metadata_t      frr_metadata;
}

struct headers {
    ethernet_t           ethernet;
    ipv4_t               ipv4;
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
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            default: accept;
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
        size = 16;
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
        size = 16;
        default_action = NoAction();
    }

    action ipv4_forward(egressSpec_t port, macAddr_t srcAddr, macAddr_t dstAddr) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = srcAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // dst_ip is switch ip.
    action ipv4_forward_to_frr() {
        meta.frr_metadata.to_frr_port = 1;
    }

    table ipv4_forward_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            ipv4_forward_to_frr;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    apply {
        // from dummy frr port
        from_frr_table.apply();
        if(meta.frr_metadata.is_frr_port == 1) {
            return;
        }

// ---------------------------your code----------------------------

// ----------------------------------------------------------------

        // ipv4 forwarding
        if(hdr.ipv4.isValid()) {
            bool result = ipv4_forward_table.apply().hit;
            if(result && meta.frr_metadata.to_frr_port == 0) {
                return;
            }
        }

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

    apply {
        // When is the case to use frr, return.
        if(meta.frr_metadata.is_frr_port == 1 || meta.frr_metadata.to_frr_port == 1) {
            return;
        }

// ---------------------------your code----------------------------

// ----------------------------------------------------------------
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);              
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
