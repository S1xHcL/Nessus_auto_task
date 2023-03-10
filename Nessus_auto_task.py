import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import os
import time
import re
import configparser


# Disable SSL and warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def get_user_info(host, ak, sk):
    url = f'{host}/session'
    headers = {
        'X-ApiKeys': f'accessKey={ak};secretKey={sk};',
        'Content-Type': 'application/json'
    }
    req = requests.get(url=url, headers=headers, verify=False).json()
    print(f"[+] 当前登录用户: {req['name']}")


def get_nessus_template_uuid(host, ak, sk, template_name="advanced"):
    headers = {
        'X-ApiKeys': f'accessKey={ak};secretKey={sk};',
        'Content-Type': 'application/json'
    }

    api = f"{host}/editor/scan/templates"
    response = requests.get(api, headers=headers, verify=False)
    templates = json.loads(response.text)['templates']

    for template in templates:
        if template['name'] == template_name:
            return template['uuid']
    return None


def create_task(host, ak, sk, create_task_name):
    task_id_list = []

    # Default task uuid
    uuid = get_nessus_template_uuid(host, ak, sk)
    if uuid is None:
        return False

    headers = {
        'X-ApiKeys': f'accessKey={ak};secretKey={sk};',
        'Content-Type': 'application/json'
    }

    url = f'{host}/scans'
    upload_file_list = upload_file(host, ak, sk)
    for task in upload_file_list:
        task_name = f'{create_task_name}_{task}'
        print(f"[!] 添加扫描任务 {task_name}")
        data = {"uuid": uuid,
                "plugins": {"SMTP problems": {"status": "enabled"}, "Backdoors": {"status": "enabled"},
                            "Rocky Linux Local Security Checks": {"status": "enabled"},
                            "Ubuntu Local Security Checks": {"status": "enabled"},
                            "Gentoo Local Security Checks": {"status": "enabled"},
                            "Oracle Linux Local Security Checks": {"status": "enabled"}, "RPC": {"status": "enabled"},
                            "Brute force attacks": {"status": "enabled"},
                            "Gain a shell remotely": {"status": "enabled"}, "Service detection": {"status": "enabled"},
                            "DNS": {"status": "enabled"}, "Mandriva Local Security Checks": {"status": "enabled"},
                            "Junos Local Security Checks": {"status": "enabled"}, "Misc.": {"status": "enabled"},
                            "FTP": {"status": "enabled"}, "Slackware Local Security Checks": {"status": "enabled"},
                            "Default Unix Accounts": {"status": "enabled"},
                            "AIX Local Security Checks": {"status": "enabled"}, "SNMP": {"status": "enabled"},
                            "OracleVM Local Security Checks": {"status": "enabled"},
                            "CGI abuses": {"status": "enabled"}, "Settings": {"status": "enabled"},
                            "CISCO": {"status": "enabled"}, "Tenable.ot": {"status": "enabled"},
                            "Firewalls": {"status": "enabled"}, "Databases": {"status": "enabled"},
                            "Debian Local Security Checks": {"status": "enabled"},
                            "Fedora Local Security Checks": {"status": "enabled"}, "Netware": {"status": "enabled"},
                            "Huawei Local Security Checks": {"status": "enabled"},
                            "Windows : User management": {"status": "enabled"},
                            "VMware ESX Local Security Checks": {"status": "enabled"},
                            "Virtuozzo Local Security Checks": {"status": "enabled"},
                            "CentOS Local Security Checks": {"status": "enabled"},
                            "Peer-To-Peer File Sharing": {"status": "enabled"},
                            "NewStart CGSL Local Security Checks": {"status": "enabled"},
                            "General": {"status": "enabled"}, "Policy Compliance": {"status": "enabled"},
                            "Amazon Linux Local Security Checks": {"status": "enabled"},
                            "Solaris Local Security Checks": {"status": "enabled"},
                            "F5 Networks Local Security Checks": {"status": "enabled"},
                            "Denial of Service": {"status": "enabled"},
                            "Windows : Microsoft Bulletins": {"status": "enabled"},
                            "SuSE Local Security Checks": {"status": "enabled"},
                            "Palo Alto Local Security Checks": {"status": "enabled"},
                            "Alma Linux Local Security Checks": {"status": "enabled"},
                            "Red Hat Local Security Checks": {"status": "enabled"},
                            "PhotonOS Local Security Checks": {"status": "enabled"},
                            "HP-UX Local Security Checks": {"status": "enabled"},
                            "CGI abuses : XSS": {"status": "enabled"},
                            "FreeBSD Local Security Checks": {"status": "enabled"}, "Windows": {"status": "enabled"},
                            "Scientific Linux Local Security Checks": {"status": "enabled"},
                            "MacOS X Local Security Checks": {"status": "enabled"},
                            "Web Servers": {"status": "enabled"}, "SCADA": {"status": "enabled"}},
                "settings": {
                    "name": task_name,
                    "enabled": "false",
                    "text_targets": "",
                    "file_targets": task
                    }
                }
        with requests.Session() as session:
            response = session.post(url, headers=headers, data=json.dumps(data), verify=False)
            if response.status_code == 200:
                data = json.loads(response.text)
                if data["scan"] is not None:
                    scan = data["scan"]
                    print(f"[+] 扫描任务已经创建，任务编号为 {scan['id']}")
                    task_id_list.append(scan['id'])
    return task_id_list


def upload_file(host, ak, sk):
    upload_file_list = []
    headers = {
        'X-ApiKeys': f'accessKey={ak};secretKey={sk};',
    }

    file_list = os.listdir('./file')
    for file_path in file_list:
        file_path = f'./file/{file_path}'
        with open(file_path, 'rb') as f:
            files = {
                'Filedata': ('{}'.format(file_path), f, 'text/plain'),
            }
            upload_url = f'{host}/file/upload'
            req = requests.post(url=upload_url, headers=headers, files=files, verify=False).json()
            upload_file_list.append(req["fileuploaded"])
            print(f"[+] 文件 {file_path} 上传成功")
    return upload_file_list


def download_html(host, ak, sk, task_id_list, create_task_name):
    with requests.Session() as session:
        for task_id in task_id_list:
            # 获取文件 token
            file_token = download_file_token(session, host, ak, sk, task_id)
            if file_token is None:
                return False
            # 判断文件状态
            status = wait_for_file_status(session, host, ak, sk, file_token)
            if status:
                url = f"{host}/tokens/{file_token}/download"
                try:
                    with session.get(url, stream=True, verify=False) as response:
                        response.raise_for_status()
                        # 获取文件名和创建输出文件夹
                        file_name = get_file_name(response)
                        file_name_path = create_output_folder(file_name, create_task_name)
                        print(f"[!] 正在导出扫描任务 {file_name} ")

                        with open(file_name_path, 'wb') as f:
                            # 逐块写入文件
                            for data in response.iter_content(chunk_size=8192):
                                f.write(data)
                        print(f"[+] 文件 {file_name} 导出成功")
                except Exception as e:
                    print(f"[-] Error while exporting files: {e}")
    return True


def get_file_name(response):
    # 从 Content-Disposition 中获取文件名
    content_disposition = response.headers.get('Content-Disposition')
    if content_disposition:
        return re.search('filename="(.+)"', content_disposition).group(1)
    else:
        return "unnamed.html"


def create_output_folder(file_name, create_task_name):
    # 创建输出文件夹
    if not os.path.exists(create_task_name):
        os.makedirs(create_task_name)
    return os.path.join(create_task_name, file_name)


def wait_for_file_status(session, host, ak, sk, file_token):
    headers = {
        'X-ApiKeys': f'accessKey={ak};secretKey={sk};',
        'Content-Type': 'application/json'
    }
    url = f'{host}/tokens/{file_token}/status'
    while True:
        response = session.get(url, headers=headers, verify=False)
        response.raise_for_status()
        status = json.loads(response.text)['status']
        if status != 'loading':
            break
        # Wait for 10 seconds before checking again
        time.sleep(100)
    return True


def download_file_token(session, host, ak, sk, task_id):
    headers = {
        'X-ApiKeys': f'accessKey={ak};secretKey={sk};',
        'Content-Type': 'application/json'
    }
    url = f'{host}/scans/{task_id}/export'
    data = {
        "format": "html",
        "template_id": 136,
        "csvColumns": {},
        "formattingOptions": {},
        "extraFilters": {"host_ids": [], "plugin_ids": []}
    }
    with session.post(url, headers=headers, data=json.dumps(data), verify=False) as response:
        response.raise_for_status()
        token = json.loads(response.text)['token']
        return token


def get_all_task_id(host, ak, sk):
    headers = {
        'X-ApiKeys': f'accessKey={ak};secretKey={sk};',
        'Content-Type': 'application/json'
    }
    url = f'{host}/scans?folder_id=3'
    response = requests.get(url, headers=headers, verify=False)
    id_list = json.loads(response.text)['scans']
    task_id_list = [task_id['id'] for task_id in id_list]
    print(f"[!] 当前一共存在 {len(task_id_list)} 个扫描任务")
    return task_id_list


def run_task(host, ak, sk, task_id):
    headers = {
        'X-ApiKeys': f'accessKey={ak};secretKey={sk};',
        'Content-Type': 'application/json'
    }
    url = f"{host}/scans/{task_id}/launch"
    response = requests.post(url, headers=headers, verify=False)
    if response.status_code != 200:
        print(f"[!] 启动 {task_id} 任务时出错 : {response.content}")
    else:
        print(f"[*] 启动 {task_id} 任务")


def get_task_status(host, ak, sk, task_id):
    url = f"{host}/scans/{task_id}"
    headers = {
        'X-ApiKeys': f'accessKey={ak};secretKey={sk};',
        'Content-Type': 'application/json'
    }
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        task_status = json.loads(response.text)['info']['status']
        print(f"[*] 正在运行 {task_id} 任务状态为 {task_status}")
        return task_status
    else:
        return None


def check_task_status(host, ak, sk, task_id_list):
    running_task = ""
    empty_task = ""
    completed_tasks = set()
    all_tasks_completed = False

    while not all_tasks_completed:
        for task_id in task_id_list:
            task_status = get_task_status(host, ak, sk, task_id)

            if task_status == "running":
                running_task = task_id
                break
            elif task_status == "empty":
                empty_task = task_id
                break
            elif task_status == "completed":
                completed_tasks.add(task_id)

        if running_task:
            while True:
                time.sleep(10)
                task_status = get_task_status(host, ak, sk, running_task)

                if task_status == "completed":
                    completed_tasks.add(running_task)
                    running_task = ""
                    break
                elif task_status == "error":
                    raise Exception(f"Task {running_task} failed with error status.")

        if empty_task:
            run_task(host, ak, sk, empty_task)
            running_task = empty_task
            empty_task = ""

        if len(completed_tasks) == len(task_id_list):
            all_tasks_completed = True

    return completed_tasks


def main():
    # 读取配置文件
    config = configparser.ConfigParser()
    config.read('config.ini')

    host = config.get('settings', 'host')
    ak = config.get('settings', 'ak')
    sk = config.get('settings', 'sk')
    create_task_name = config.get('settings', 'create_task')
    get_user_info(host, ak, sk)
    # 批量创建任务
    task_id_list = create_task(host, ak, sk, create_task_name)
    # 获取所有任务 id
    task_id_list = get_all_task_id(host, ak, sk)
    # 监控并持续化运行所有任务
    check_task_status(host, ak, sk, task_id_list)
    # 下载所有任务报告
    download_html(host, ak, sk, task_id_list, create_task_name)


if __name__ == '__main__':
    main()