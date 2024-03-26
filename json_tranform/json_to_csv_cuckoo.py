import json
import csv

# Xây dựng class Event Process
class Event_Process :
    def __init__(self, ProcessID, ParentPID, CreationTimestamp, CommandLine, Image, ProcessType, FileType, Files, Modules, Low_Access, Autostart, Priority):
        self.ProcessID = ProcessID
        self.ParentPID = ParentPID
        self. CreationTimestamp =  CreationTimestamp
        self.CommandLine = CommandLine
        self.Image  = Image
        self.ProcessType = ProcessType
        self.FileType = FileType
        self.Files = Files
        self.Modules = Modules
        self.Low_Access = Low_Access
        self.Autostart = Autostart
        self.Priority = Priority

#Xây dựng class Registry Event        
class  Registry_Event : 
    def __init__(self, Registry, HKEY_LOCAL_MACHINE, HKEY_CLASSES_ROOT, HKEY_USERS, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER,Startup_registry_keys, Active_setup_registry_keys, Services_registry_keys, DLL_injection_registry_keys, Shell_spawning_registry_keys, Internet_settings_registry_keys, BHO_registry_keys):
        self.Registry = Registry
        self.HKEY_LOCAL_MACHINE = HKEY_LOCAL_MACHINE
        self.HKEY_CLASSES_ROOT = HKEY_CLASSES_ROOT
        self.HKEY_USERS = HKEY_USERS
        self.HKEY_CURRENT_CONFIG = HKEY_CURRENT_CONFIG
        self.HKEY_CURRENT_USER= HKEY_CURRENT_USER
        self.Startup_registry_keys = Startup_registry_keys
        self.Active_setup_registry_keys = Active_setup_registry_keys
        self.Services_registry_keys = Services_registry_keys
        self.DLL_injection_registry_keys = DLL_injection_registry_keys
        self.Shell_spawning_registry_keys = Shell_spawning_registry_keys
        self.Internet_settings_registry_keys = Internet_settings_registry_keys
        self.BHO_registry_keys = BHO_registry_keys

#Xây dựng class Network Connection
class Network_Connection:
    def __init__(self,Scores_NetWork,Events_Count_Network,IP_Domain_HTTP_Request,Unknown_IP_Domain_Request,Suspicious_IP_Domain_Request,Malicious_IP_Domain_Request,Whitelist_IP_Domain_Request,Unsafe_IP_Domain_Request ,IP_score,Domain_score,Request_score):
        self.Scores_NetWork = Scores_NetWork
        self.Events_Count_Network = Events_Count_Network
        self.IP_Domain_HTTP_Request = IP_Domain_HTTP_Request
        self.Unknown_IP_Domain_Request = Unknown_IP_Domain_Request
        self.Suspicious_IP_Domain_Request = Suspicious_IP_Domain_Request
        self.Malicious_IP_Domain_Request = Malicious_IP_Domain_Request
        self.Whitelist_IP_Domain_Request = Whitelist_IP_Domain_Request
        self.Unsafe_IP_Domain_Request = Unsafe_IP_Domain_Request
        self.IP_score = IP_score
        self.Domain_score = Domain_score
        self.Request_score = Request_score
        
#Xây dựng class Event File Delete     
class Event_File_Delete:
    def __init__(self,Drop_Files,Total_drop_file_size,Users,RECYCLE_BIN,Windows,ProgramData,Program_Files,Program_Files_x86,Perflogs,OneDriveTemp,WinREAgent,Type_XML,Type_Image,Type_HTML,Type_Text,Type_Executable):
        self.Drop_Files = Drop_Files
        self.Total_drop_file_size= Total_drop_file_size
        self.Users = Users
        self.RECYCLE_BIN = RECYCLE_BIN
        self.Windows = Windows
        self.ProgramData = ProgramData
        self.Program_Files = Program_Files
        self.Program_Files_x86 = Program_Files_x86
        self.Perflogs = Perflogs
        self.OneDriveTemp = OneDriveTemp
        self.WinREAgent = WinREAgent
        self.Type_XML = Type_XML
        self.Type_Image = Type_Image
        self.Type_HTML = Type_HTML
        self.Type_Text = Type_Text
        self.Type_Executable = Type_Executable

#Xây dựng class Kêt quả       
class Sample_result:
    def __init__(self,Event_Process,Registry_Event,Network_Connection,Event_File_Delete):
        self.Event_Process = Event_Process
        self.Registry_Event = Registry_Event
        self.Network_Connection = Network_Connection
        self.Event_File_Delete = Event_File_Delete
        
# Xây dựng class phần tiến trình trong generic bao gồm số lượng file tiến trình đã tạo và các thư mục liên quan đến registry mà tiến trình đã truy cập    
class generic:
    def __init__(self,file_created ,link_paths):
        self.file_created = file_created
        self.link_paths = link_paths

# Lấy thông tin các tiến trình của mấu
def get_Event_Process(data):
    #Tạo danh sách tiến trình
    list_processes = data['behavior']['processes'] if 'behavior' in data and 'processes' in data['behavior'] else []
    list_generic = data['behavior']['generic'] if 'behavior' in data and 'generic' in data['behavior'] else []

    # Tạo danh sách lưu số file mà tiến trình đã tạo
    processes_generic = {}
    
    for process in list_generic:
        ProcessID = process['pid'] if 'pid' in process else 0
        
        # Lấy số lượng file tiến trình đã tạo
        file_created = len(process['summary']['file_created']) if 'summary' in process and 'file_created' in process['summary'] else 0
            
        # Lấy các thư mục liên quan đến registry mà tiến trình đã truy cập
        list_regkey = []
        link_paths = []
        #Thêm các thư mục nằm trong regkey_read
        if 'summary' in process and 'regkey_read' in process['summary']:
            for link in process['summary']['regkey_read']:
                list_regkey.append(link)
                paths = link.split('\\')
                for path in paths:
                    link_paths.append(path)
        #Thêm các thư mục nằm trong regkey_written
        if 'summary' in process and 'regkey_written' in process['summary']:
            for link in process['summary']['regkey_written']:
                list_regkey.append(link)
                paths = link.split('\\')
                for path in paths:
                    link_paths.append(path)
                
        #Thêm các thư mục nằm trong regkey_openned
        if 'summary' in process and 'regkey_opened' in process['summary']:
            for link in process['summary']['regkey_opened']:
                list_regkey.append(link)
                paths = link.split('\\')
                for path in paths:
                    link_paths.append(path)
        
        # Lưu giá trị mỗi tiến trình
        processes_generic[ProcessID] = generic(file_created,link_paths)
        
    # Tạo danh sách lưu kết quả của các tiến trình  
    processes={}
    
    # Tạo giá trị cần lưu lại + giá trị kiểm tra xem đã ghi lại tiến trình cần lưu chưa (tạm coi là tiến trình đầu tiên)
    main_process = 0
    check_save_process = False
    

    # Duyệt thông tin các tiến trình để thêm vào danh sách kết quả
    for process in list_processes :
        ProcessID = process['pid'] if 'pid' in process else 0
        ParentPID = process['ppid'] if 'ppid' in process else 0
        CreationTimestamp = process['time'] if 'time' in process else 0
        CommandLine = process['command_line'] if 'command_line' in process else ''
        Image = process['process_path'] if 'process_path' in process else ''
        ProcessType = process['type'] if 'tyoe' in process else 0
        FileType = process['file_type'] if 'file_type' in process else ''
        Files = processes_generic[ProcessID].file_created if ProcessID in processes_generic else 0
        Modules = len(process['modules']) if 'modules' in process else 0
        
        # Kiểm tra xem tiến trình có low acess hay không
        Low_Access = False
        if 'low_access' in process:
            Low_Access = process['low_access']
        
        # Kiểm tra xem tiến trình có autostart hay không
        Autostart = False
        list_Autostart_registry_keys = ['Run','RunOnce','StartUp']
        for path in list_Autostart_registry_keys:
            if path in processes_generic[ProcessID].link_paths:
                Autostart = True
                break
            
        # Kiểm tra xem tiến trình có được ưu tiên hay không
        Priority = 0
        if 'priority' in process:
            Priority = process['priority']
            
        processes[ProcessID] = Event_Process(ProcessID, ParentPID, CreationTimestamp, CommandLine, Image, ProcessType, FileType, Files, Modules, Low_Access, Autostart, Priority)
        
        if (not check_save_process) or ProcessType == 'Main process':
            main_process = ProcessID
            check_save_process = True
    
    return processes[main_process] 
    
# Lấy thông tin các registry đã sử dụng 
def get_Registry_Event(data):
    # Tạo danh sách lưu tất cả các thư mục liên quan đến regisry mà tiến trình đã duyệt qua 
    link_paths = []

    # Tạo danh sách lưu các registry mà tiến trình đã sử dụng
    list_regkey = []
    #Thêm các thư mục nằm trong regkey_read
    if 'behavior' in data and 'summary' in data['behavior'] and 'regkey_read' in data['behavior']['summary']:
        for link in data['behavior']['summary']['regkey_read']:
            list_regkey.append(link)
            paths = link.split('\\')
            for path in paths:
                link_paths.append(path)
            
    #Thêm các thư mục nằm trong regkey_written
    if 'behavior' in data and 'summary' in data['behavior'] and 'regkey_written' in data['behavior']['summary']:
        for link in data['behavior']['summary']['regkey_written']:
            list_regkey.append(link)
            paths = link.split('\\')
            for path in paths:
                link_paths.append(path)
            
    #Thêm các thư mục nằm trong regkey_openned
    if 'behavior' in data and 'summary' in data['behavior'] and 'regkey_opened' in data['behavior']['summary']:
        for link in data['behavior']['summary']['regkey_opened']:
            list_regkey.append(link)
            paths = link.split('\\')
            for path in paths:
                link_paths.append(path)

    # Lấy số lượng các regisry đã sử dụng và các loại registry đã sử dụng
    Registry  = len(list_regkey)
    HKEY_LOCAL_MACHINE = link_paths.count('HKEY_LOCAL_MACHINE')
    HKEY_CLASSES_ROOT = link_paths.count('HKEY_CLASSES_ROOT') 
    HKEY_USERS= link_paths.count('HKEY_USERS') 
    HKEY_CURRENT_CONFIG= link_paths.count('HKEY_CURRENT_CONFIG') 
    HKEY_CURRENT_USER= link_paths.count('HKEY_CURRENT_USER')

    # Kiểm tra xem mẫu có sử dụng Startup_registry_keys không
    Startup_registry_keys = False
    list_Startup_registry_keys = ['Run','RunOnce','RunServices','StartUp']
    for path in list_Startup_registry_keys:
        if path in link_paths:
            Startup_registry_keys = True
            break

    # Kiểm tra xem mẫu có sử dụng Active_setup_registry_keys hay không
    Active_setup_registry_keys = False
    list_Active_setup_registry_keys = ['Active Setup']
    for path in list_Active_setup_registry_keys:
        if path in link_paths:
            Active_setup_registry_keys = True
            break

    # Kiểm tra xem mẫu có sử dụng Services_registry_keys hay không
    Services_registry_keys = False
    list_Services_registry_keys = ['Services']
    for path in list_Services_registry_keys:
        if path in link_paths:
            Services_registry_keys = True
            break

    # Kiểm tra xem mẫu có sử dụng Services_registry_keys hay không
    DLL_injection_registry_keys = False
    list_DLL_injection_registry_keys = ['AppInit_DLLs','LoadAppInit_DLLs','KnownDLLs']
    for path in list_DLL_injection_registry_keys:
        if path in link_paths:
            DLL_injection_registry_keys = True
            break
        
    # Kiểm tra xem mẫu có sử dụng Services_registry_keys hay không
    Shell_spawning_registry_keys = False
    list_Shell_spawning_registry_keys = ['shell','command','cmd']
    for path in list_Shell_spawning_registry_keys:
        if path in link_paths:
            Shell_spawning_registry_keys = True
            break
        
    # Kiểm tra xem mẫu có sử dụng Services_registry_keys hay không
    Internet_settings_registry_keys = False
    list_Internet_settings_registry_keys = ['Internet','Internet Settings']
    for path in list_Internet_settings_registry_keys:
        if path in link_paths:
            Internet_settings_registry_keys = True
            break
        
    # Kiểm tra xem mẫu có sử dụng Services_registry_keys hay không
    BHO_registry_keys = False
    list_BHO_registry_keys = ['Browser Helper Objects']
    for path in list_BHO_registry_keys:
        if path in link_paths:
            BHO_registry_keys = True
            break
        
    return Registry_Event(Registry, HKEY_LOCAL_MACHINE, HKEY_CLASSES_ROOT, HKEY_USERS, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER,Startup_registry_keys, Active_setup_registry_keys, Services_registry_keys, DLL_injection_registry_keys, Shell_spawning_registry_keys, Internet_settings_registry_keys, BHO_registry_keys)

#Lấy kết quả về kết nối mạng
def get_Network_Connection(data):
    # Lấy thông tin về network
    network = data['network'] if 'network' in data else {}
    
    # Kiểm tra xem mẫu có kết nối internet hay không
    list_access = ["tls","udp","dns_servers","http","icmp","smtp","tcp","smtp_ex","hosts","dns","http_ex","domains","dead_hosts","irc","https_ex"]
    internet = []
    for kind_access in list_access:
        if kind_access in network:
            for path in network[kind_access]:
                internet.append(path)
    
    if len(internet)==0:
        Scores_NetWork = False
    else :
        Scores_NetWork = True
        
    # Lấy kết quả số lần kết nối mạng của mẫu
    Events_Count_Network = len(internet)
    
    # Tính số lượng IP , Domain, HTTP request
    
    # lấy dang sách IP
    list_find_IP = ["dns_servers","hosts","dns"]
    list_IP = []
    for kind_access in list_find_IP:
        if kind_access in network:
            for path in network[kind_access]:
                list_IP.append(path)
                
    # lấy dang sách IP
    list_find_Domain = ["dns_servers","hosts","dns"]
    list_Domain = []
    for kind_access in list_find_Domain:
        if kind_access in network:
            for path in network[kind_access]:
                list_Domain.append(path)
                
    # lấy dang sách IP
    list_find_Request = ["dns_servers","hosts","dns"]
    list_Request = []
    for kind_access in list_find_Request:
        if kind_access in network:
            for path in network[kind_access]:
                list_Request.append(path)
                
    IP_Domain_HTTP_Request = len(list_IP)+len(list_Domain)+len(list_Request)
    # Lấy số lượng mỗi loại IP
    Unknown_IP = 0
    Suspicious_IP = 0
    Whitelist_IP = 0
    Malicious_IP = 0
    Unsafe_IP = 0
    
    for Ip in list_IP:
        if Ip['Type']==0:
            Unknown_IP+=1
        elif Ip['Type']==1:
            Suspicious_IP+=1
        elif Ip['Type']==2:
            Whitelist_IP+=1
        elif Ip['Type']==3:
            Malicious_IP+=1
        else : 
            Unsafe_IP+=1
            
    # Lấy số lượng mỗi loại Domain
    Unknown_Domain = 0
    Suspicious_Domain = 0
    Whitelist_Domain = 0
    Malicious_Domain = 0
    Unsafe_Domain = 0
    
    for domain in list_Domain:
        if domain['Type']==0:
            Unknown_Domain+=1
        elif domain['Type']==1:
            Suspicious_Domain+=1
        elif domain['Type']==2:
            Whitelist_Domain+=1
        elif domain['Type']==3:
            Malicious_Domain+=1
        else : 
            Unsafe_Domain+=1
    
    # Lấy số lượng mỗi loại Request
    Unknown_Request = 0
    Suspicious_Request = 0
    Whitelist_Request = 0
    Malicious_Request = 0
    Unsafe_Request = 0
    
    for request in list_Request:
        if request['Type']==0:
            Unknown_Request+=1
        elif request['Type']==1:
            Suspicious_Request+=1
        elif request['Type']==2:
            Whitelist_Request+=1
        elif request['Type']==3:
            Malicious_Request+=1
        else : 
            Unsafe_Request+=1
    
    # Tính tổng số lượng mỗi loại
    Unknown_IP_Domain_Request= Unknown_IP + Unknown_Domain + Unknown_Request
    Suspicious_IP_Domain_Request= Suspicious_IP + Suspicious_Domain + Suspicious_Request
    Malicious_IP_Domain_Request= Malicious_IP + Malicious_Domain + Malicious_Request
    Whitelist_IP_Domain_Request= Whitelist_IP + Whitelist_Domain + Whitelist_Request
    Unsafe_IP_Domain_Request = Unsafe_IP + Unsafe_Domain + Unsafe_Request
    
    # Tính điểm cho IP,Domain,Request
    IP_score = (Unknown_IP * 0 + Suspicious_IP * 1 + Malicious_IP * 2 + Whitelist_IP * 3 + Unsafe_IP * 4)/5
    Domain_score= (Unknown_Domain * 0 + Suspicious_Domain * 1 + Malicious_Domain * 2 + Whitelist_Domain * 3 + Unsafe_Domain * 4)/5
    Request_score = (Unknown_Request * 0 + Suspicious_Request * 1 + Malicious_Request * 2 + Whitelist_Request * 3 + Unsafe_Request * 4)/5
    
    return Network_Connection(Scores_NetWork,Events_Count_Network,IP_Domain_HTTP_Request,Unknown_IP_Domain_Request,Suspicious_IP_Domain_Request,Malicious_IP_Domain_Request,Whitelist_IP_Domain_Request,Unsafe_IP_Domain_Request ,IP_score,Domain_score,Request_score)

# Lấy thông tin về các file đã xóa
def get_Event_File_Delete(data):
    # Lấy thông tin về file bị xóa
    if 'behavior' in data and 'summary' in data['behavior'] and 'file_deleted' in data['behavior']['summary']:
        file_deteled = data['behavior']['summary']['file_deleted']
    
    Drop_Files = len(file_deteled)
    Total_drop_file_size = 0
    
    # Tạo danh sách lưu các folder chứa file mà mẫu đã xóa và danh sách kiểu file mà mẫu đã xóa
    list_folders = []
    list_extensions = []
    
    # Duyệt từng đường dẫn đến file
    for link_file in file_deteled:
        # Tách từng phần đẻ lưu vào danh sách
        folder_paths = link_file.split('\\')
        for path in folder_paths:
            list_folders.append(path)
            
        # Lưu kiểu file bằng cách lấy xâu từ dấu chấm cuối cùng
        list_extensions.append(link_file[link_file.rfind('.')+1:-1])
        
    Users = 'Users' in list_folders
    RECYCLE_BIN = '$RECYCLE_BIN' in list_folders
    Windows = 'Windows' in list_folders
    ProgramData = 'ProgramData' in list_folders
    Program_Files = 'Program Files' in list_folders
    Program_Files_x86 = 'Program Files (x86)' in list_folders
    Perflogs = 'Perflogs' in list_folders
    OneDriveTemp = 'OneDriveTemp'in list_folders
    WinREAgent = '$WinREAgent' in list_folders
    Type_XML = list_extensions.count('xml')
    Type_Image = list_extensions.count('iso')
    Type_HTML = list_extensions.count('html')
    Type_Text = list_extensions.count('txt')
    Type_Executable = list_extensions.count('exe')
    
    return Event_File_Delete(Drop_Files,Total_drop_file_size,Users,RECYCLE_BIN,Windows,ProgramData,Program_Files,Program_Files_x86,Perflogs,OneDriveTemp,WinREAgent,Type_XML,Type_Image,Type_HTML,Type_Text,Type_Executable)

# Lấy điểm đánh giá
def get_Score(data):
    if 'info' in data and 'score' in data['info']:
        return data['info']['score']
    return 0

# Lấy kết quả
def get_sample_result(data):
    return Sample_result(get_Event_Process(data),get_Registry_Event(data),get_Network_Connection(data),get_Event_File_Delete(data))    


# Ghi kết quả lần đầu
def first_data(Result):
    # Đường dẫn tới tệp CSV 
    csv_file_path = "sample.csv"

    # Ghi dữ liệu vào tệp CSV
    with open(csv_file_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        
    # Viết tiêu đề
        writer.writerow(['ProcessID.Event_Process','ParentPID.Event_Process','CreationTimestamp.Event_Process','CommandLine.Event_Process','Image.Event_Process','ProcessType.Event_Process','FileType.Event_Process','Files.Event_Process','Modules.Event_Process','Low_Access.Event_Process','Autostart.Event_Process','Priority.Event_Process',
                        'Registry.Registry_Event','HKEY_LOCAL_MACHINE.Registry_Event','HKEY_CLASSES_ROOT.Registry_Event','HKEY_USERS.Registry_Event','HKEY_CURRENT_CONFIG.Registry_Event','HKEY_CURRENT_USER.Registry_Event','Startup_registry_keys.Registry_Event','Active_setup_registry_keys.Registry_Event','Services_registry_keys.Registry_Event','DLL_injection_registry_keys.Registry_Event','Shell_spawning_registry_keys.Registry_Event','Internet_settings_registry_keys.Registry_Event','BHO_registry_keys.Registry_Event',
                        'Scores_NetWork.Network_Connection','Events_Count_Network.Network_Connection','IP_Domain_HTTP_Request.Network_Connection','Unknown_IP_Domain_Request.Network_Connection','Suspicious_IP_Domain_Request.Network_Connection','Malicious_IP_Domain_Request.Network_Connection','Whitelist_IP_Domain_Request.Network_Connection','Unsafe_IP_Domain_Request .Network_Connection','IP_score.Network_Connection','Domain_score.Network_Connection','Request_score.Network_Connection',
                        'Drop_Files.Event_File_Delete','Total_drop_file_size.Event_File_Delete','Users.Event_File_Delete','RECYCLE_BIN.Event_File_Delete','Windows.Event_File_Delete','ProgramData.Event_File_Delete','Program_Files.Event_File_Delete','Program_Files_x86.Event_File_Delete','Perflogs.Event_File_Delete','OneDriveTemp.Event_File_Delete','WinREAgent.Event_File_Delete','Type_XML.Event_File_Delete','Type_Image.Event_File_Delete','Type_HTML.Event_File_Delete','Type_Text.Event_File_Delete','Type_Executable.Event_File_Delete',
                        'Score'])
        
        # Viết dũ liệu vào file csv
        writer.writerow([Result.Event_Process.ProcessID,Result.Event_Process.ParentPID,Result.Event_Process.CreationTimestamp,Result.Event_Process.CommandLine,Result.Event_Process.Image,Result.Event_Process.ProcessType,Result.Event_Process.FileType,Result.Event_Process.Files,Result.Event_Process.Modules,Result.Event_Process.Low_Access,Result.Event_Process.Autostart,Result.Event_Process.Priority,
                        Result.Registry_Event.Registry,Result.Registry_Event.HKEY_LOCAL_MACHINE,Result.Registry_Event.HKEY_CLASSES_ROOT,Result.Registry_Event.HKEY_USERS,Result.Registry_Event.HKEY_CURRENT_CONFIG,Result.Registry_Event.HKEY_CURRENT_USER,Result.Registry_Event.Startup_registry_keys,Result.Registry_Event.Active_setup_registry_keys,Result.Registry_Event.Services_registry_keys,Result.Registry_Event.DLL_injection_registry_keys,Result.Registry_Event.Shell_spawning_registry_keys,Result.Registry_Event.Internet_settings_registry_keys,Result.Registry_Event.BHO_registry_keys,
                        Result.Network_Connection.Scores_NetWork,Result.Network_Connection.Events_Count_Network,Result.Network_Connection.IP_Domain_HTTP_Request,Result.Network_Connection.Unknown_IP_Domain_Request,Result.Network_Connection.Suspicious_IP_Domain_Request,Result.Network_Connection.Malicious_IP_Domain_Request,Result.Network_Connection.Whitelist_IP_Domain_Request,Result.Network_Connection.Unsafe_IP_Domain_Request ,Result.Network_Connection.IP_score,Result.Network_Connection.Domain_score,Result.Network_Connection.Request_score,
                        Result.Event_File_Delete.Drop_Files,Result.Event_File_Delete.Total_drop_file_size,Result.Event_File_Delete.Users,Result.Event_File_Delete.RECYCLE_BIN,Result.Event_File_Delete.Windows,Result.Event_File_Delete.ProgramData,Result.Event_File_Delete.Program_Files,Result.Event_File_Delete.Program_Files_x86,Result.Event_File_Delete.Perflogs,Result.Event_File_Delete.OneDriveTemp,Result.Event_File_Delete.WinREAgent,Result.Event_File_Delete.Type_XML,Result.Event_File_Delete.Type_Image,Result.Event_File_Delete.Type_HTML,Result.Event_File_Delete.Type_Text,Result.Event_File_Delete.Type_Executable,])
        
#Ghi thêm kết quả mới vào file csv có sẵn

def add_data(Result):
    csv_file_path = "sample.csv"

    # Ghi dữ liệu vào tệp CSV
    with open(csv_file_path, mode='a', newline='') as file:
        writer = csv.writer(file)
        
        # Viết dũ liệu vào file csv
        writer.writerow([Result.Event_Process.ProcessID,Result.Event_Process.ParentPID,Result.Event_Process.CreationTimestamp,Result.Event_Process.CommandLine,Result.Event_Process.Image,Result.Event_Process.ProcessType,Result.Event_Process.FileType,Result.Event_Process.Files,Result.Event_Process.Modules,Result.Event_Process.Low_Access,Result.Event_Process.Autostart,Result.Event_Process.Priority,
                        Result.Registry_Event.Registry,Result.Registry_Event.HKEY_LOCAL_MACHINE,Result.Registry_Event.HKEY_CLASSES_ROOT,Result.Registry_Event.HKEY_USERS,Result.Registry_Event.HKEY_CURRENT_CONFIG,Result.Registry_Event.HKEY_CURRENT_USER,Result.Registry_Event.Startup_registry_keys,Result.Registry_Event.Active_setup_registry_keys,Result.Registry_Event.Services_registry_keys,Result.Registry_Event.DLL_injection_registry_keys,Result.Registry_Event.Shell_spawning_registry_keys,Result.Registry_Event.Internet_settings_registry_keys,Result.Registry_Event.BHO_registry_keys,
                        Result.Network_Connection.Scores_NetWork,Result.Network_Connection.Events_Count_Network,Result.Network_Connection.IP_Domain_HTTP_Request,Result.Network_Connection.Unknown_IP_Domain_Request,Result.Network_Connection.Suspicious_IP_Domain_Request,Result.Network_Connection.Malicious_IP_Domain_Request,Result.Network_Connection.Whitelist_IP_Domain_Request,Result.Network_Connection.Unsafe_IP_Domain_Request ,Result.Network_Connection.IP_score,Result.Network_Connection.Domain_score,Result.Network_Connection.Request_score,
                        Result.Event_File_Delete.Drop_Files,Result.Event_File_Delete.Total_drop_file_size,Result.Event_File_Delete.Users,Result.Event_File_Delete.RECYCLE_BIN,Result.Event_File_Delete.Windows,Result.Event_File_Delete.ProgramData,Result.Event_File_Delete.Program_Files,Result.Event_File_Delete.Program_Files_x86,Result.Event_File_Delete.Perflogs,Result.Event_File_Delete.OneDriveTemp,Result.Event_File_Delete.WinREAgent,Result.Event_File_Delete.Type_XML,Result.Event_File_Delete.Type_Image,Result.Event_File_Delete.Type_HTML,Result.Event_File_Delete.Type_Text,Result.Event_File_Delete.Type_Executable,])


# Hàm main

# Đường dẫn đền folder
source_folder = r'D:\University\Science Research\Data\2021_Normal'

from get_file_paths import get_file_paths

list_paths = get_file_paths(source_folder)
# Đọc dư liệu trong file json
for source in list_paths:
    source = source.replace('\\','/')
    with open(source,'r') as f:
        data = f.read()
        data = json.loads(data)  

    # Lấy kết quả của mẫu đang xét
    Result = get_sample_result(data)

    # Ghi kết quả đầu tiên vào file csv
    first_data(Result)