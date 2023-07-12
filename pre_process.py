# -*- coding:utf-8 -*-
# @FileName  :pre_process.py
# @Author    :Yin Yi
from torch_geometric.data import Data
import torch
import networkx as nx
import leidenalg as la

cvestr = "CVE-2011-2411,CVE-2012-2969,CVE-2011-5000,CVE-2010-3614,CVE-2019-9641,CVE-2009-3767,CVE-2017-3167,CVE-2010-2730,CVE-2015-3276,CVE-2016-0777,CVE-2018-7185,CVE-2022-23943,CVE-2020-1934,CVE-2020-8623,CVE-2014-2324,CVE-2020-8624,CVE-2014-MATCHED,CVE-1999-1322,CVE-2005-2090,CVE-2017-7679,CVE-2019-6470,CVE-2009-0025,CVE-2017-9798,CVE-2019-3880,CVE-2013-4434,CVE-2011-1783,CVE-2016-8858,CVE-2019-0215,CVE-2018-19520,CVE-2011-5279,CVE-2020-9490,CVE-2008-0455,CVE-2018-20685,CVE-2007-5156,CVE-2016-6170,CVE-2011-3607,CVE-2017-9798,CVE-2000-0216,CVE-2010-2068,CVE-2017-3145,CVE-2015-2808,CVE-2013-1896,CVE-2021-41617,CVE-2009-4444,CVE-2016-4979,CVE-2021-28041,CVE-2014-1692,CVE-2015-1763,CVE-2016-0778,CVE-2005-2088,CVE-2013-3576,CVE-2012-0250,CVE-2012-4575,CVE-2020-15778,CVE-2015-MATCHED,CVE-2008-4300,CVE-2020-8622,CVE-2010-3972,CVE-2014-0226, CVE-2008-1446,CVE-2015-1761,CVE-2012-MATCHED,CVE-2006-4924,CVE-2021-25219,CVE-2014-0001,CVE-2022-22721,CVE-2018-5741,CVE-2016-6291,CVE-2016-8858,CVE-1999-MATCHED,CVE-2010-1899,CVE-2012-0021,CVE-2019-6470,CVE-2008-2939,CVE-2012-4558,CVE-2008-4359,CVE-2018-17189,CVE-2013-4846,CVE-2016-8612,Other"
cve_p = cvestr.split(",")
osstr = "Liunx、FreeBSD、windows、Windows Server、Cisco、Ubuntu、CentOS"
portstr = "21，22，23，25，80，110，443，995，1433，3128，3306，3389，5900，8000，8080，8081，8443"
servicestr = "FTP，HTTP，SSH，MYSQL，SMTP，Telnet，POP3，IMAP，HTTPS，SQLServer，Windows Server Remote Desktop Services，DNS，L2TP"
windowstr = "1460、2048、4096、8192、16384"
netpro_p = ["IP", "ICMPv6"]
speedstr = "B=50，N=100/ms,B=10，N=100/ms,B=50，N=20/ms"
speed_p = speedstr.split(",")
lable_p=["应用层服务器设备","网络存储设备","云服务设备","安全防护设备","路由器交换设备","人机交互设备","物联网设备","其他设备"]
window_p = windowstr.split("、")
service_p = servicestr.split("，")
post_p = portstr.split("，")
os_p = osstr.split("、")


class IPinf():
    def __init__(self, ip, vector,lable):
        self.ip = ip;
        self.vector = vector;
        self.lable=lable


# def iidcheck(ip):
#     if "::" in ip:


def getListIP() -> list:
    result = []
    with open("node.txt")as file:
        for line in file.readlines():
            elems = line.split(" ")
            ip = elems[0]
            iid = elems[1]
            suffix = elems[2]
            ports = elems[3]
            services = elems[4]
            transport_protocol = elems[5]
            windows = elems[6]
            ttls = elems[7]
            netpro = elems[8]
            speed_ICMP = elems[9]
            os = elems[10]
            cves = elems[11]
            # 匿名节点的向量处理方式
            lable = elems[12]
            if '*' in ip:
                vector = torch.zeros([1, 169], dtype=torch.float32)
                vector[0][3] = 1
                vector[0][14] = 1
                vector[0][32] = 1
                vector[0][46] = 1
                vector[0][49] = 1
                vector[0][55] = 1
                vector[0][73] = 1
                vector[0][76] = 1
                vector[0][80] = 1
                cves_p = cves.split("-")
                for i in cves_p:
                    index = cves_p.index(i)
                    vector[0][index + 81] = 1
                if os in os_p:
                    os_index = os.index(os)
                    vector[0][161 + os_index] = 1
                else:
                    vector[0][168] = 1
                lable_v=torch.zeros([1,8],dtype=torch.float32)
                lable_v[0][lable_p.index(lable)]
                ipinf = IPinf(ip, vector,lable_v)
                result.append(ipinf)
                continue
            iid_v = torch.zeros([1, 4], dtype=torch.float32)
            iid_v[0][int(iid) - 1] = 1
            suffix_v = torch.zeros([1, 10], dtype=torch.float32)
            if iid == 1:
                suffix_v[0][iid - 1] = 1
            else:
                suffix_v[0][-1] = 1
            ports = ports.split("-")
            port_v = torch.zeros([1, 18], dtype=torch.float32)
            for i in ports:
                if i in post_p:
                    port_index = post_p.index(i)
                    port_v[0][port_index] = 1
                else:
                    port_v[0][17] = 1
            service_v = torch.zeros([1, 14], dtype=torch.float32)
            services = services.split("-")
            for i in services:
                if i in service_p:
                    service_index = service_p.index(i)
                    service_v[0][service_index] = 1
                else:
                    service_v[0][13] = 1
            transport_p_v = torch.zeros([1, 3], dtype=torch.float32)
            if transport_protocol == "TCP":
                transport_p_v[0][0] = 1
            elif transport_protocol == "UDP":
                transport_p_v[0][1] = 1
            else:
                transport_p_v[0][2] = 1
            windows_v = torch.zeros([1, 6], dtype=torch.float32)
            if windows in window_p:
                windows_index = window_p.index(windows)
                windows_v[0][windows_index] = 1
            else:
                windows_v[0][-1] = 1
            ttls = ttls.split("-")
            ttl = min(map(ttls, int))
            ttl_v = torch.zeros([1, 18], dtype=torch.float32)
            if ttl >= 18:
                ttl_v[0][-1] = 1
            else:
                ttl_v[0][ttl - 1] = 1
            netpro_v = torch.zeros([1, 3], dtype=torch.float32)
            if netpro in netpro_p:
                netpro_index = netpro_p.index(netpro)
                netpro_v[0][netpro_index] = 1
            else:
                netpro_v[0][-1] = 1
            speed_v = torch.zeros([1, 4], dtype=torch.float32)
            if netpro == "ICMPv6":
                if speed_ICMP in speed_p:
                    speed_index = speed_p.index(speed_ICMP)
                    speed_v[0][speed_index] = 1
                else:
                    speed_v[0][-1] = 1
            else:
                speed_v[0][-1] = 1
            cves_p = cves.split("-")
            cve_v = torch.zeros([1, 80], dtype=torch.float32)
            for i in cves_p:
                index = cves_p.index(i)
                cve_v[0][index] = 1
            os_v = torch.zeros([1, 8], dtype=torch.float32)
            if os in os_p:
                os_index = os.index(os)
                os_v[0][os_index] = 1
            else:
                vector[0][168] = 1
            vector = torch.cat((iid_v, suffix_v), dim=-1)
            vector = torch.cat((vector, port_v), dim=-1)
            vector = torch.cat((vector, service_v), dim=-1)
            vector = torch.cat((vector, transport_p_v), dim=-1)
            vector = torch.cat((vector, windows_v), dim=-1)
            vector = torch.cat((vector, ttl_v), dim=-1)
            vector = torch.cat((vector, windows_v), dim=-1)
            vector = torch.cat((vector, netpro_v), dim=-1)
            vector = torch.cat((vector, speed_v), dim=-1)
            vector = torch.cat((vector, cve_v), dim=-1)
            vector = torch.cat((vector, os_v), dim=-1)
            lable_v = torch.zeros([1, 8], dtype=torch.float32)
            lable_v[0][lable_p.index(lable)]
            ipinf = IPinf(ip, vector, lable_v)
            result.append(ipinf)
        return result


def getGrpah():
    # 得到划分完成的子图
    feats = getListIP()
    graph = nx.Graph()
    for node in feats:
        graph.add_node(node.ip, feat=node.vector,lable=node.lable)
    with open("edge.txt")as file:
        for edge in file.readlines():
            ips = edge.split(" ")
            graph.add_edge(ips[0], ips[1])
    partition = la.find_partition(graph, la.ModularityVertexPartition)
    subgraphs = list(partition)
    subgraph_objects = [nx.Graph(graph.subgraph(nodes)) for nodes in subgraphs]
    return subgraph_objects
