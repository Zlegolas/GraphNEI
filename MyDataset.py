# -*- coding:utf-8 -*-
# @FileName  :MyDataset.py
# @Author    :Yin Yi
from torch_geometric.data import Dataset,Data
import torch

class MyDataset(Dataset):
    def __init__(self, data_list):
        self.data_list = data_list
        self.dataset=[]
        for graph in data_list:
            x=[]
            y=[]
            for node in graph.nodes:
                x.append(node["feat"])
                y.append(node["lable"])
            edge_index = torch.tensor(list(graph.edges)).t().contiguous()
            data=Data(x=x,edge_index=edge_index,y=y)
            self.dataset.append(data)


    def __len__(self):
        return len(self.data_list)

    def __getitem__(self, index):
        data = self.dataset[index]
        return data