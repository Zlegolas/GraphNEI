import torch
import torch.nn as nn

class attention_weights(nn.Module):
    def __init__(self, input_dim):
        super(attention_weights, self).__init__()
        self.input_dim = input_dim
        self.query = nn.Linear(input_dim, input_dim)
        self.key = nn.Linear(input_dim, input_dim)
        self.value = nn.Linear(input_dim, input_dim)
        self.softmax = nn.Softmax(dim=-1)

    def forward(self, x):
        query = self.query(x)
        key = self.key(x)
        value = self.value(x)
        scores = torch.matmul(query, key.transpose(-1, -2)) / torch.sqrt(torch.tensor(self.input_dim).float())
        attention_weights = self.softmax(scores)
        return attention_weights