from scapy.all import *
from scapy.contrib.pfcp import *
from scapy.layers.inet import IP

# Configurar QER com uma taxa básica
pfcpSESReqWithQER = PFCP(version=1, S=1, seq=3, seid=0, spare_oct=0) / \
    PFCPSessionEstablishmentRequest(IE_list=[
        IE_CreateFAR(IE_list=[
            IE_ApplyAction(FORW=1),
            IE_FAR_Id(id=1),
            IE_ForwardingParameters(IE_list=[
                IE_DestinationInterface(interface="Access"),
                IE_NetworkInstance(instance="access"),
                IE_OuterHeaderCreation(GTPUUDPIPV4=1, TEID=0x01000000, ipv4="127.0.0.1"),
            ])
        ]),
        IE_CreatePDR(IE_list=[
            IE_FAR_Id(id=1),
            IE_OuterHeaderRemoval(header="GTP-U/UDP/IPv4"),
            IE_PDI(IE_list=[
                IE_FTEID(V4=1, TEID=0x104c9033, ipv4="172.18.1.2"),
                IE_NetworkInstance(instance="access"),
                IE_SourceInterface(interface="Access"),
            ]),
            IE_PDR_Id(id=1),
            IE_Precedence(precedence=100)
        ]),
        IE_CreateQER(IE_list=[
            IE_QER_Id(id=1),
            IE_FAR_Id(id=1),
            # Adicione apenas os campos básicos disponíveis
            IE_MaximumBitrate_UL(bitrate=100000000),  # Limite de taxa em bits por segundo
            IE_MaximumBitrate_DL(bitrate=100000000)   # Limite de taxa em bits por segundo
        ]),
        IE_FSEID(v4=1, seid=0xffde7230bf97810a, ipv4="172.18.1.1"),
        IE_NodeId(id_type="FQDN", id="BIG-IMPORTANT-CP")
    ])

# Enviar a requisição com QER
target = IP(dst="127.0.0.1") / UDP(sport=33100, dport=8805)

print("Sending PFCP Session Setup Request with QER")
ans = sr1(target / pfcpSESReqWithQER, iface='lo')
print(ans.show())

