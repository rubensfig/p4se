#pragma once

#include <core.p4>
#include <tna.p4>

#include "Open-Tofino/p4-examples/p4_16_programs/common/headers.p4"
#include "Open-Tofino/p4-examples/p4_16_programs/common/util.p4"

#define PARSER_INGRESS 	      parser SwitchIngressParser(packet_in pkt, out headers_t hdr, out metadata_t ig_md, out ingress_intrinsic_metadata_t ig_intr_md)
#define CTL_INGRESS_DEPARSER  control SwitchIngressDeparser(packet_out pkt, inout headers_t hdr, in metadata_t ig_md, in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
#define CTL_INGRESS           control SwitchIngress(inout headers_t hdr, inout metadata_t ig_md, in ingress_intrinsic_metadata_t ig_intr_md, in ingress_intrinsic_metadata_from_parser_t ig_prsr_md, inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md, inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
#define PARSER_EGRESS         parser SwitchEgressParser(packet_in pkt, out headers_t hdr, out metadata_t eg_md, out egress_intrinsic_metadata_t eg_intr_md)
#define CTL_EGRESS_DEPARSER   control SwitchEgressDeparser(packet_out pkt, inout headers_t hdr, in metadata_t eg_md, in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
#define CTL_EGRESS            control SwitchEgress(inout headers_t hdr, inout metadata_t eg_md, in egress_intrinsic_metadata_t eg_intr_md, in egress_intrinsic_metadata_from_parser_t eg_prsr_md, inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md, inout egress_intrinsic_metadata_for_output_port_t eg_oport_md)

#define MARK_TO_DROP()         ig_dprsr_md.drop_ctl = 1

#define SET_EGRESS_PORT(value) ig_tm_md.ucast_egress_port = value
#define GET_INGRESS_PORT       ig_intr_md.ingress_port

/*******************************************************************************
 * BNG Pipelines
 */
#define CTL_INGRESSDOWNSTREAM   control IngressDownstream(inout headers_t hdr, inout metadata_t ig_md, in ingress_intrinsic_metadata_t ig_intr_md, in ingress_intrinsic_metadata_from_parser_t ig_prsr_md, inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md, inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
#define CTL_INGRESSUPSTREAM     control IngressUpstream(inout headers_t hdr, inout metadata_t ig_md, in ingress_intrinsic_metadata_t ig_intr_md, in ingress_intrinsic_metadata_from_parser_t ig_prsr_md, inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md, inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
