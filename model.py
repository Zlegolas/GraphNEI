from torch_geometric.nn import MessagePassing
import networkx as nx
from torch_geometric.utils import to_networkx
import SelfAttention
import torch
import torch.nn.parameter as p


class GraphNEI(MessagePassing):
    def __init__(self,):
        super(GraphNEI, self).__init__()
        self.attention = SelfAttention.attention_weights(input_dim=169)
        self.p1=p(torch.tensor(1.0))
        self.p2 = p(torch.tensor(1.0))
        self.p3 = p(torch.tensor(1.0))
        self.l=torch.nn.Linear(in_features=15,out_features=8)
        self.s=torch.nn.functional.softmax()

    def forward(self, data):
        feat = data.x
        edge_index = data.edge_index
        # 计算注意力矩阵
        attw = self.attention(feat)
        graph = to_networkx(data)
        # 计算接近中心性
        closeness_centrality = nx.closeness_centrality(graph)
        re=[]
        for index, node in enumerate(feat):
            # 遍历邻居集合
            index_neiighbors = self.getNeighbors(index, edge_index)
            node_feat = []
            for i in index_neiighbors:
                node_feat.append(feat[i])
            res = []
            for j in range(len(feat)):
                neighbors = self.getNeighbors(j, edge_index)
                j_feat = []
                for num in neighbors:
                    j_feat.append(feat[num])
                jacccard =self.jaccard_similarity(node_feat,j_feat)
                res.append(jacccard)
            res=torch.tensor(res,dtype=torch.float32)
            NW=self.p1*attw[index]+self.p2*closeness_centrality+self.p3*res
            top_values, top_indices = torch.topk(NW, k=10)
            # gengxin
            for i in top_indices:
                feat[index]=feat[index]+feat[i]
            soft=self.l(feat[index])
            r=self.s(soft)
            if (max(r)>0.5)[0]:
                re.append(7)
            else:
                re.append(max(r))
        return torch.tensor(re,dtype=torch.float32)





    def getNeighbors(self, index, edge_index) -> set:
        neighbors = set()
        for neiighbor in edge_index:
            if edge_index[0][neiighbor] == index or edge_index[1][neiighbor] == index:
                neighbors.add(neiighbor)
        return neighbors

    def jaccard_similarity(self, node1_neighbors, node2_neighbors):
        s = set(node1_neighbors)
        s1 = 0
        for i in node2_neighbors:
            s.add(i)
        for i in node1_neighbors:
            if i in node2_neighbors:
                s1 = s1 + 1
        if s1 == 0:
            return 0.0
        else:
            return s1 / len(s)
