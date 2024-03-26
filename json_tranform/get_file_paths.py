import os

def get_file_paths(directory):
    file_paths = []  # Danh sách chứa đường dẫn của các tệp
    
    # Duyệt qua tất cả các tệp và thư mục trong thư mục đầu vào
    for root, directories, files in os.walk(directory):
        for filename in files:
            # Tạo đường dẫn tuyệt đối của tệp
            file_path = os.path.join(root, filename)
            # Thêm đường dẫn vào danh sách
            file_paths.append(file_path)
    
    return file_paths
