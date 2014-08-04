#!/usr/bin/python

from Exscript import Account
from Exscript.util.interact import read_login
from Exscript.protocols import SSH2
from Exscript.protocols.drivers import ios
import re
import json
import argparse
import getpass
import sys

class Host_connection:

    def __init__(self, host, command_line_credentials = True, credentials = {}):

        """
        Initializing function. It takes one mandatory and two optional arguments. Function use provided host and credentials to create conn instance used to connect to device.

        Arguments:
        host -- IP address or hostname of the device
        command_line_credentials -- True(default) -> login credentials are provided during script execution
                                 -- False -> login credentails should be provided during class initialization
        credentials -- Must be provided if command_line_credentials == False. The format of the variable must be dictionary with 'username' and 'password' as keys.
        """

        self.host = host
        self.credentials = credentials
        self.account = Account(self.credentials['username'],self.credentials['password'])


    def connect_to_device(self):
        """
        Function for SSH connection to the Cisco device. It creates connection instance. Exscript module is used for connection establishment and command execution. Function also execute 'terminal length 0' command on the Cisco device to ensure that command whole output is displayed.
        """

        self.conn = SSH2()
        self.conn.set_driver('ios')
        try:
            self.conn.connect(self.host)
        except:
            return {'msg': 'Unable to connect to the device'}
        try:
            self.conn.login(self.account)
        except:
            return {'msg': 'Authentication failed.'}
        self.conn.execute('terminal length 0')
        return {}

    def execute_command(self,command):

        """
        Function to execute command on the Cisco device. It takes command as argument and return command output string.

        Arguments:
        command -- valid command on the Cisco device in string format
        """

        try:
            self.conn.execute(command)
            command_response = self.conn.response
            return {'command_response': command_response}
        except:
            return {'msg': 'Command execution failed.'}
        


    def disconnect_device(self):

        """
        Function used to disconnect SSH session from the device. It takes no arguments.
        """
        
        self.conn.send('\exit\r')
        self.conn.close()


class Access_lists(Host_connection):

    running_config = ''

    def get_running_config(self, force = False):

        """
        Function that execute 'show running-config' command on the Cisco device and stores returned string to the running_config variable. Function only execute command if varible running_config is empty string. You can force command execution independently of the running_config variable with the force argument.

        Arguments:
        force -- False(default) -> command is not executed if running config already exists
              -- True -> 'show running-config' even if running_config variable exists
        """

        if self.running_config == '' or force:
            response = self.execute_command('show running-config')
            if 'msg' in response.keys():
                self.running_config = {'msg': 'Unable to get running configuration'}
            else:
                self.running_config = {'config': response['command_response']}

    def get_string_position(self,search_string):
        
        """
        Function takes search string and string arguments. It check for all search_strng iterations in running_config variable. It returns the list of positions for all iterations of the search_string in the string.

        Arguments:
        search_string -- regex in the string format
        running_config -- string that contains running configuration 
        """

        string_pos = []
        search_result = re.finditer(search_string,self.running_config['config'])
        for result in search_result:
            string_pos.append([result.start(0), result.end(0)])
        return string_pos        

    def get_list_of_numbered_access_lists(self):

        """
        Function parse access-list numbers from the numbered access-lists. It returns list of numbered access-lists.
        """

        self.get_running_config()
        if 'msg' in self.running_config.keys():
            return {'msg': 'Unable to get running configuration.'}
        access_lists = []
        string_pos = self.get_string_position('access-list \d* .*\r\n')
        for pos in string_pos:
            access_lists.append(self.running_config['config'][pos[0]:pos[1]-2].split(' ')[1])
        print access_lists
        return {'acls': list(set(access_lists))}

    def get_list_of_named_access_lists(self):

        """
        Function parse names of the access-lists that exists on the network device. It returns the list of access-lists names.
        """

        self.get_running_config()
        if 'msg' in self.running_config.keys():
            return {'msg': 'Unable to get running configuration.'}
        access_lists = []
        string_pos = self.get_string_position('ip access-list (extended|standard) .*\r\n')
        for pos in string_pos:
            access_lists.append(self.running_config['config'][pos[0]:pos[1]-2].split(' ')[3])
        return {'acls': access_lists}

    def get_list_of_all_access_lists(self):
    
        """
        Function returns the list of all access-lists that exists on the network device.
        """

        list_of_numbered_access_lists = self.get_list_of_numbered_access_lists()
        if 'msg' in list_of_numbered_access_lists:
            return list_of_numbered_access_lists
        list_of_named_access_lists = self.get_list_of_named_access_lists()
        if 'msg' in list_of_named_access_lists:
            return list_of_named_access_lists
        return {'acls': list_of_numbered_access_lists['acls']+list_of_named_access_lists['acls']}

    def get_access_list(self,access_list):

        """
        Function is used to get called access-list. It takes access-list string as argument and determinates if access-list is numbered or named.

        Arguments:
        access_list -- access-list id in the string format
        """

        try:
            int(access_list)
            return self.get_numbered_access_list(access_list)
        except ValueError:
            return self.get_named_access_list(access_list)

    def get_numbered_access_list(self,access_list_number):

        """
        Function takes access_list_number as argument and returns the type and access-list entries for the numbered access-list that was called by the functions. The result is returned in dictionary format, with type and entries used as keys. The type returns access-list type, which could be standard or extended and entries return list of access-list entries. If access-list does not exist on the network device, the function returns empty dictionary.

        Arguments:
        access_list_number -- access-list number in the string format
        """

        access_list = {}
        access_list_type = self.get_numbered_access_list_type(access_list_number)
        if 'msg' in access_list_type.keys():
            return {'msg': 'Access-list number is out of range for Cisco IOS devices.'}
        access_list[access_list_number] = {'type': access_list_type['type']}
        access_list_entries = self.parse_numbered_access_list(access_list_number)
        if 'msg' in access_list_entries:
            return access_list_entries
        access_list[access_list_number]['entries'] = access_list_entries
        return access_list

    def get_named_access_list(self,access_list_name):

        """
        Function takes access_list_name as argument and returns the type and access-list entries for the named access-list that was called by the functions. The result is returned in dictionary format, with type and entries used as keys. The type returns access-list type, which could be standard or extended and entries return list of access-list entries. If access-list does not exist on the network device, the function returns empty dictionary.

        Arguments:
        access_list_name -- access-list name in the string format.
        """

        access_list = {}
        access_list_type = self.get_named_access_list_type(access_list_name)
        if 'msg' in access_list_type.keys():
            return access_list_type
        access_list[access_list_name] = {'type': access_list_type['type']}

        access_list_value = self.parse_named_access_list(access_list_name)
        if 'msg' in access_list_value.keys():
            return access_list_value
        access_list[access_list_name]['entries'] = access_list_value['entries']
        return access_list

    def get_all_numbered_access_lists(self):

        """
        The function returns all numbered access-lists with type and access-list entries.
        """

        list_of_access_lists = []
        list_of_all_numbered_access_lists = self.get_list_of_numbered_access_lists()
        if 'msg' in list_of_all_numbered_access_lists:
            return {'msg': 'Unable to get list of numbered access_lists.'}
        for access_list in list_of_all_numbered_access_lists['acls']:
            numbered_access_list = self.get_numbered_access_list(access_list)
            if 'msg' in numbered_access_list:
                return numbered_access_list 
            list_of_access_lists.append(numbered_access_list)
        return {'acls': list_of_access_lists}

    def get_all_named_access_lists(self):

        """
        The function returns all named access-lists with type and access-list entries.
        """

        list_of_access_lists = []
        list_of_all_named_access_lists = self.get_list_of_named_access_lists()
        if 'msg' in list_of_all_named_access_lists:
            return {'msg': 'Unable to get list of named access_lists.'}
        for access_list in self.get_list_of_named_access_lists()['acls']:
            named_access_list = self.get_named_access_list(access_list)
            if 'msg' in named_access_list:
                return named_access_list 
            list_of_access_lists.append(self.named_access_list(access_list))
        return {'acls':list_of_access_lists}

    def get_all_access_lists(self):

        """
        The function returns all numbered and named access-list.
        """

        list_of_numbered_access_lists = self.get_list_of_numbered_access_lists()
        if 'msg' in list_of_numbered_access_lists:
            return list_of_numbered_access_lists
        list_of_named_access_lists = self.get_list_of_named_access_lists()
        if 'msg' in list_of_named_access_lists:
            return list_of_named_access_lists
        return {'acls': list_of_numbered_access_lists['acls']+list_of_named_access_lists['acls']}
        return self.get_all_numbered_access_lists() + self.get_all_named_access_lists()

    def get_numbered_access_list_type(self,access_list_number):

        """
        The function is used to classify numbered access-list. It takes access_list_number as arguments and returns access-list type.

        Arguments:
        access_list_number -- access-list number in string format 
        """

        if int(access_list_number) >= 1 and int(access_list_number) <= 99:
            return {'type':'standard'}
        elif int(access_list_number) >= 100 and int(access_list_number) <= 199:
            return {'type':'extended'}
        elif int(access_list_number) >= 1300 and int(access_list_number) <= 1999:
            return {'type':'standard'}
        elif int(access_list_number) >= 2000 and int(access_list_number) <= 2699:
            return {'type':'extended'}
        else:
            return {'msg':'error'}

    def get_named_access_list_type(self,access_list_name):

        """
        Function is used to determine the type of named access-lists. It takes name as argument.

        Arguments:
        access_list_name -- access-list name in string format
        """


        self.get_running_config()
        if 'msg' in self.running_config.keys():
            return {'msg': 'Unable to get running configuration.'}
        string_pos = self.get_string_position('ip access-list (extended|standard) ' + access_list_name + '\r\n')
        if not string_pos:
            return {'msg': 'Access-list does not exist.'}
        for pos in string_pos:
            access_list_type = self.running_config['config'][pos[0]:pos[1]-2].split(' ')[2]
        return {'type': access_list_type}

    def parse_numbered_access_list(self,access_list_number):

        """
        Function is used to parse numbered access-list from running-config. It takes access-list number as an argument.

        Arguments:
        access_list_number -- access-list number in string format
        """

        self.get_running_config()
        if 'msg' in self.running_config.keys():
            return {'msg': 'Unable to get running configuration.'}
        access_list_entries = {}
        counter = 1
        string_pos = self.get_string_position('access-list ' + access_list_number + ' ' + '.*\r\n')
        if not string_pos:
            return {'msg': 'Access-list does not exist on the device.'}
        for pos in string_pos:
            access_list_entries[counter] = self.running_config['config'][pos[0]:pos[1]-2]
            counter = counter + 1


        
        return access_list_entries

    def parse_named_access_list(self,access_list_name):

        """
        Function is used to parse named access-list from running-config. It takes access-list name as an argument.
        
        Arguments:
        access_list_name -- access-list name in string format
        """


        self.get_running_config()
        if 'msg' in self.running_config.keys():
            return {'msg': 'Unable to get running configuration.'}
        access_list_entries = []
        string_pos = self.get_string_position('ip access-list (extended|standard) ' + access_list_name + '\r\n')
        if not string_pos:
            return {'msg': 'Access-list does not exist on the device.'}
        for pos in string_pos:
            access_list_command = self.running_config['config'][pos[0]:pos[1]-2]
            access_list_entry_position = self.running_config['config'].find(access_list_command) + len(access_list_command)
            in_access_list = True
            access_list_entries = {}
            counter = 1
            while in_access_list:
                if self.running_config['config'][access_list_entry_position + 2] == ' ':
                    access_list_entry_stop = self.running_config['config'][access_list_entry_position+2:].find('\r\n')
                    access_list_entries[counter] = self.running_config['config'][access_list_entry_position+3:access_list_entry_position+2+access_list_entry_stop]
                    counter = counter + 1
                    access_list_entry_position = access_list_entry_position + 2 + access_list_entry_stop
                else:
                    in_access_list = False


        return {'entries': access_list_entries}

    def delete_access_list_entry(self,access_list,entry_id):

        """

        """
    
        try:
            int(access_list)
            return self.delete_numbered_access_list_entry(access_list,entry_id)
        except ValueError:
            return self.delete_named_access_list_entry(access_list,entry_id)        

    def delete_numbered_access_list_entry(self,access_list_number,entry_id_list):

        """

        """
        
        self.get_running_config()
        if 'msg' in self.running_config.keys():
            return {'msg': 'Unable to get running configuration.'}
        access_list_entries = self.get_numbered_access_list(access_list_number)
        if 'msg' in access_list_entries.keys():
            return access_list_entries
        try:
            for entry in entry_id_list:
                del access_list_entries[access_list_number]['entries'][int(entry)]
        except KeyError:
            return {'msg': 'Access-list entry does not exist in access-list'}

        command_response = self.execute_command('configure terminal')
        if 'msg' in command_response.keys():
            return {'msg': 'Unable to enter configuration mode.'}
        command_response = self.execute_command('no access-list ' + access_list_number)
        if 'msg' in command_response.keys():
            return {'msg': 'Unable to delete access-list.'}

        if not len(entry_id_list) == 0:
            for key in sorted(access_list_entries[access_list_number]['entries'].keys()):
                command_response = self.execute_command(access_list_entries[access_list_number]['entries'][key])
                if 'msg' in command_response:
                    return {'msg': 'Unable to configure access-list entry.'}
        command_response = self.execute_command('exit')
        if 'msg' in command_response.keys():
            return {'msg': 'Unable to exit configuration mode'}

        self.get_running_config(force=True)
        if 'msg' in self.running_config.keys():
            return {'msg': 'Unable to get running configuration.'}
        return self.get_numbered_access_list(access_list_number)

    def delete_named_access_list_entry(self,access_list_name,entry_id_list):

        """

        """
       
        self.get_running_config()
        if 'msg' in self.running_config.keys():
            return {'msg': 'Unable to get running configuration.'}
        access_list_entries = self.get_named_access_list(access_list_name)
        if 'msg' in access_list_entries.keys():
            return access_list_entries
        try:
            for entry in entry_id_list:
                del access_list_entries[access_list_name]['entries'][int(entry)]
        except KeyError:
            return {'msg': 'Access-list entry does not exist in access-list'}

        command_response = self.execute_command('configure terminal')
        if 'msg' in command_response.keys():
            return {'msg': 'Unable to enter configuration mode.'}
        
        command_response = self.execute_command('no ip access-list ' + access_list_entries[access_list_name]['type'] + ' ' + access_list_name)
        if 'msg' in command_response.keys():
            return {'msg': 'Unable to delete access-list.'}
        if not len(access_list_entries[access_list_name]['entries']) == 0 and not len(entry_id_list) == 0:
            command_response = self.execute_command('ip access-list ' + access_list_entries[access_list_name]['type'] + ' ' + access_list_name)
            if 'msg' in command_response:
                return {'msg': 'Unable to re-apply access-list'}
            for key in sorted(access_list_entries[access_list_name]['entries'].keys()):
                command_response = self.execute_command(access_list_entries[access_list_name]['entries'][key])
                if 'msg' in command_response:
                    return {'msg': 'Unable to apply access-list entry'}
        command_response = self.execute_command('end')
        if 'msg' in command_response:
            return {'msg': 'Unable to exit access-list configuration mode'}

        self.get_running_config(force=True)
        if 'msg' in self.running_config.keys():
            return {'msg': 'Unable to get running configuration.'}
        return self.get_named_access_list(access_list_name)
 
    def add_access_list_entry(self,access_list,entry_id,access_list_entry):

        """

        """
    
        try:
            int(access_list)
            return self.add_numbered_access_list_entry(access_list,entry_id,access_list_entry)
        except ValueError:
            return self.add_named_access_list_entry(access_list,entry_id,access_list_entry)  

    def add_numbered_access_list_entry(self,access_list_number,entry_id,access_list_entry):

        """
        Pri standarni ni nujno da je sekvenca pravilna, lahko je out-of-order
        """

        self.get_running_config()
        if 'msg' in self.running_config.keys():
            return {'msg': 'Unable to get running configuration.'}
        access_list_entries = self.get_numbered_access_list(access_list_number)
        if 'msg' in access_list_entries.keys():
            return access_list_entries
        try:
            int(entry_id)
        except:
            return {'msg': 'Entry id must be number.'}

        new_access_list_entries = {int(entry_id):access_list_entry}
        print new_access_list_entries
        for key in access_list_entries[access_list_number]['entries'].keys():
            if key < int(entry_id):
                new_access_list_entries[key] = access_list_entries[access_list_number]['entries'][key]
            else:
                new_access_list_entries[key+1] = access_list_entries[access_list_number]['entries'][key]

        command_response = self.execute_command('configure terminal')
        if 'msg' in command_response.keys():
            return {'msg': 'Unable to enter configuration mode.'}
        command_response = self.execute_command('no access-list ' + access_list_number)
        if 'msg' in command_response.keys():
            return {'msg': 'Unable to delete access-list.'}


        for key in sorted(new_access_list_entries.keys()):
            command_response = self.execute_command(new_access_list_entries[key])
            if 'msg' in command_response.keys():
                return {'msg': 'Access-list entry syntax error.'}
        command_response = self.execute_command('exit')
        if 'msg' in command_response.keys():
            return {'msg': 'Unable to exit configuration mode'}

        self.get_running_config(force=True)
        if 'msg' in self.running_config.keys():
            return {'msg': 'Unable to get running configuration.'}
        return self.get_numbered_access_list(access_list_number)

    def add_named_access_list_entry(self,access_list_name,entry_id,access_list_entry):

        """

        """

        self.get_running_config()
        if 'msg' in self.running_config.keys():
            return {'msg': 'Unable to get running configuration.'}
        access_list_entries = self.get_named_access_list(access_list_name)
        if 'msg' in access_list_entries.keys():
            return access_list_entries

        try:
            int(entry_id)
        except:
            return {'msg': 'Entry id must be number.'}

        new_access_list_entries = {int(entry_id):access_list_entry}
        for key in access_list_entries[access_list_name]['entries'].keys():
            if key < int(entry_id):
                new_access_list_entries[key] = access_list_entries[access_list_name]['entries'][key]
            else:
                new_access_list_entries[key+1] = access_list_entries[access_list_name]['entries'][key]


        command_response = self.execute_command('configure terminal')
        if 'msg' in command_response.keys():
            return {'msg': 'Unable to enter configuration mode.'}
        self.execute_command('no ip access-list ' + access_list_entries[access_list_name]['type'] + ' ' + access_list_name)
        if 'msg' in command_response.keys():
            return {'msg': 'Unable to delete access-list.'}
        self.execute_command('ip access-list ' + access_list_entries[access_list_name]['type'] + ' ' + access_list_name)
        if 'msg' in command_response.keys():
            return {'msg': 'Unable to add access-list.'}
        for key in sorted(new_access_list_entries.keys()):
            command_response = self.execute_command(new_access_list_entries[key])
            if 'msg' in command_response:
                return {'msg': 'Access-list entry syntax error.'}
        command_response = self.execute_command('end')
        if 'msg' in command_response:
            return {'msg': 'Unable to exit access-list configuration mode'}

        self.get_running_config(force=True)
        if 'msg' in self.running_config.keys():
            return {'msg': 'Unable to get running configuration.'}
        return self.get_named_access_list(access_list_name)



if __name__ == '__main__':


    parser = argparse.ArgumentParser(prog='./acl.py',description='Cisco access-list parser.')
    parser.add_argument('-host', metavar='host', help='The IP or hostname of the device', required=True)
    parser.add_argument('-user', metavar='username', help='The username for the device')
    parser.add_argument('-pass', metavar='password', help='The password for the device')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-acl', metavar='acl_id', help='The name or number of the access-list')
    group.add_argument('-list', help='Get list of access-lists', action='store_true')
    group.add_argument('-del', metavar=('acl_id','acl_entry_id'), nargs='+', help='Delete access-list or access-list entries from the access-list')
    group.add_argument('-add', metavar=('acl_id','acl_entry_id','entry'), nargs=3, help='Add new entry to the access-list')

    args = vars(parser.parse_args())
    print args 
    if args['user'] == None:
        args['user'] = raw_input('Username: ')
    if args['pass'] == None:
        args['pass'] = getpass.getpass()
    credentials = {'username':args['user'],'password':args['pass']}


    access_lists = Access_lists(args['host'],credentials = credentials)
    connection_message = access_lists.connect_to_device()    
    if 'msg' in connection_message.keys():
        print connection_message['msg']
        sys.exit()

#    access_lists.execute_command('configure terminal')
    if args['list'] == True:
        function_response = access_lists.get_list_of_all_access_lists()
        if 'msg' in function_response:
            print function_response['msg']
        else:
            print json.dumps(function_response['acls'], indent=4)
    elif args['acl'] != None:
        access_list_value = access_lists.get_access_list(args['acl'])
        if 'msg' in access_list_value.keys():
            print access_list_value['msg']
        else:
            print json.dumps(access_list_value, indent=4)
    elif args['del'] != None:
        access_list_value = access_lists.delete_access_list_entry(args['del'][0],args['del'][1:])
        if 'msg' in access_list_value.keys():
            print access_list_value['msg']
        else:
            print json.dumps(access_list_value, indent=4)
    elif args['add'] != None:
        access_list_value = access_lists.add_access_list_entry(args['add'][0],args['add'][1],args['add'][2])
        if 'msg' in access_list_value.keys():
            print access_list_value['msg']
        else:
            print json.dumps(access_list_value['acls'], indent=4)
    else:
        print json.dumps(access_lists.get_all_access_lists(), indent=4)


    

    access_lists.disconnect_device()

