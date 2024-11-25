import paramiko

def ssh_command(ip, port, user, passwd, cmd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
    client.connect(ip, port=port, username=user, password=passwd)
    
    _, stdout, stdaddr = client.exec_command(cmd)
    output = stdout.readlines() + stdaddr.readlines()
    if output:
        print('----Output----')
        for line in output:
            print(line.strip())
            
if __name__ == '__main__':
    import getpass
    #user = getpass.getuser()
    ##if using above function, it will use the username from the user running the script.
    ##using the function below allows us to enter a username for remote execution.
    user = input('Username: ')
    password = getpass.getpass()
    
    ip = input('Enter server IP: ') or '192.168.1.203'
    port = input('Enter port or <CR>: ') or 2222
    cmd = input('Enter command or <CR>: ') or 'id'
    ssh_command(ip, port, user, password, cmd)
