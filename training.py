from model import GraphNEI
from MyDataset import MyDataset
from torch_geometric.data import DataLoader
import torch.optim as optim
import torch

model = GraphNEI()
dataset = MyDataset()
loss = torch.nn.CrossEntropyLoss()
dataloader = DataLoader(dataset, batch_size=32, shuffle=True)
optimizer = optim.Adam(model.parameters(), lr=0.01)
model.train()
for i in range(150):
    for index, graph in enumerate(dataloader):
        graph, y = graph
        optimizer.zero_grad()  # 优化器清零
        outputs = model(graph)
        loss.backward()
        optimizer.step()
        print("loss:",loss)
