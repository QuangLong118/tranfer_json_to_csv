import json
# Đường dẫn đền file json
source = 'D:/University/Science Research/Data/2021_Normal/exe/000be4af-a4bc-4f33-8a7e-d7be7cc8cdd9.json'

# Đọc dư liệu trong file json
with open(source,'r') as f:
    data = f.read()
    data = json.loads(data)  
      
for x in data :
    print(x)
    