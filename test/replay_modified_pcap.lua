package.path = package.path ..";?.lua;test/?.lua;app/?.lua;"

pktgen.page("range");
pktgen.screen("off");

pktgen.range.src_mac("all", "mode", 1);
pktgen.range.dst_mac("all", "mode", 0);

pktgen.range.src_ip("all", "mode", "2");
pktgen.range.dst_ip("all", "mode", 3);

pktgen.range.src_port("all", "mode", 2);
pktgen.range.dst_port("all", "mode", 3);

pktgen.range.modify_pcap("all", "mode", 1);
