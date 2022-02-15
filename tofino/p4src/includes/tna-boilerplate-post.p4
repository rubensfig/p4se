#pragma once

Pipeline(SwitchIngressParser(),
SwitchIngress(),
SwitchIngressDeparser(),
SwitchEgressParser(),
SwitchEgress(),
SwitchEgressDeparser()) pipe;

Switch(pipe) main;
