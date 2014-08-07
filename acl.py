from Exscript import Account
from Exscript.util.interact import read_login
from Exscript.protocols import SSH2
from Exscript.protocols.drivers import ios
import re
import json
import argparse
import getpass
import sys


msg_unable_to_connect = 'Unable to connect to the device.'
msg_authentication_failed = 'Authentication failed.'
msg_command_failed = 'Command execution failed.'
msg_running_config_failed = 'Unable to get running configuration'
msg_numbered_out_of_range = 'Access-list number is out of range for Cisco IOS devices.'
msg_access_list_does_not_exist = 'Access-list does not exist on the device.'
msg_access_list_entry_does_not_exist = 'Access-list entry does not exist in access-list.'
msg_unable_to_enter_config_mode = 'Unable to enter configuration mode.'
msg_unable_to_delete_access_list = 'Unable to delete access-list.'
msg_unable_to_configure_entry = 'Unable to configure access-list entry.'
msg_unable_to_exit_config_mode = 'Unable to exit configuration mode.'
msg_unable_to_apply_access_list = 'Unable to apply access-list.'
msg_entry_number = 'Entry id must be number.'
msg_access_list_syntax = 'Access-list entry syntax error.'


class ExceptionTemplate(Exception):
    def __init__(self,msg):
        self.msg = msg
    def __str__(self):
        return self.msg

class ConnectionError(ExceptionTemplate): pass
class AuthenticationError(ExceptionTemplate): pass
class CommandError(ExceptionTemplate): pass
class RunningConfigError(ExceptionTemplate): pass
class NumberedOutOfRangeError(ExceptionTemplate): pass
class AccessListNotExistError(ExceptionTemplate): pass
class AccessListEntryNotExistError(ExceptionTemplate): pass
class UnableToEnterConfigModeError(ExceptionTemplate): pass
class UnableToDeleteAccessListError(ExceptionTemplate): pass
class UnableToConfigureEntryError(ExceptionTemplate): pass
class UnableToExitConfigModeError(ExceptionTemplate): pass
class UnableToApplyAccessListError(ExceptionTemplate): pass
class EntryNumberError(ExceptionTemplate): pass
class AccessListSyntaxError(ExceptionTemplate): pass

class Host_connection:

    def __init__(self, host, credentials = {}):
        """
        Initializing function. 

        Init function takes host and credentials to connect to the device.

        Keyword arguments:
        host(format string) -- IP address or hostname of the device
        credentials(format dictionary) -- The variable must be dictionary with 'username' and 'password' as keywords.

        Returns:

        Error messages:
        """

        self.host = host
        self.credentials = credentials
        self.account = Account(self.credentials['username'],self.credentials['password'])

    def connect_to_device(self):
        """
        Function to connect to the device.

        Function is used to create connection instance. It uses Exscript module to connect to device via SSH. Function also execute 'terminal length 0' command on the Cisco device to ensure that whole output is displayed.

        Keyword arguments:
        
        Returns:
        Empty dictionary

        Error messages:
        msg_unable_to_connect -- Message is displayed when connection to the device fails.
        msg_authentication_failed -- Message is displayed when authentication to the device fail.
        """

        self.conn = SSH2()
        self.conn.set_driver('ios')
        try:
            self.conn.connect(self.host)
        except:
            raise ConnectionError(msg_unable_to_connect)
        try:
            self.conn.login(self.account)
        except:
            raise AuthenticationError(msg_authentication_failed)
        self.conn.execute('terminal length 0')

    def execute_command(self,command):
        """
        Command execution function.

        Function executes command on the Cisco device. It takes command as argument and return command output string.

        Keyword arguments:
        command(format: string) -- command to execute on the Cisco device

        Returns:
        command output(
        """

        try:
            self.conn.execute(command)
            command_response = self.conn.response
            return {'command_response': command_response}
        except:
            raise CommandError(msg_command_failed)
        


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
            try:
                response = self.execute_command('show running-config')
            except CommandError:
                raise RunningConfigError(msg_running_config_failed)
            self.running_config = {'config': response['command_response']}
        return self.running_config

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
        access_lists = []
        string_pos = self.get_string_position('access-list \d* .*\r\n')
        for pos in string_pos:
            access_lists.append(self.running_config['config'][pos[0]:pos[1]-2].split(' ')[1])
        return {'acls': list(set(access_lists))}

    def get_list_of_named_access_lists(self):

        """
        Function parse names of the access-lists that exists on the network device. It returns the list of access-lists names.
        """

        self.get_running_config()
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
        list_of_named_access_lists = self.get_list_of_named_access_lists()
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
        access_list[access_list_number] = {'type': access_list_type['type']}
        access_list_entries = self.parse_numbered_access_list(access_list_number)
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
        access_list[access_list_name] = {'type': access_list_type['type']}
        access_list_value = self.parse_named_access_list(access_list_name)
        access_list[access_list_name]['entries'] = access_list_value['entries']
        return access_list

    def get_all_numbered_access_lists(self):

        """
        The function returns all numbered access-lists with type and access-list entries.
        """

        list_of_access_lists = []
        list_of_all_numbered_access_lists = self.get_list_of_numbered_access_lists()
        for access_list in list_of_all_numbered_access_lists['acls']:
            numbered_access_list = self.get_numbered_access_list(access_list)
            list_of_access_lists.append(numbered_access_list)
        return {'acls': list_of_access_lists}

    def get_all_named_access_lists(self):

        """
        The function returns all named access-lists with type and access-list entries.
        """

        list_of_access_lists = []
        list_of_all_named_access_lists = self.get_list_of_named_access_lists()
        for access_list in self.get_list_of_named_access_lists()['acls']:
            named_access_list = self.get_named_access_list(access_list)
            list_of_access_lists.append(self.named_access_list(access_list))
        return {'acls':list_of_access_lists}

    def get_all_access_lists(self):

        """
        The function returns all numbered and named access-list.
        """

        list_of_numbered_access_lists = self.get_list_of_numbered_access_lists()
        list_of_named_access_lists = self.get_list_of_named_access_lists()
        list_of_all_access_lists = list_of_numbered_access_lists['acls'] + list_of_named_access_lists['acls']
        all_access_lists = []
        for acl in list_of_all_access_lists:
            all_access_lists.append(self.get_access_list(acl))
        return {'acls': all_access_lists}


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
            raise NumberedOutOfRangeError(msg_numbered_out_of_range)

    def get_named_access_list_type(self,access_list_name):

        """
        Function is used to determine the type of named access-lists. It takes name as argument.

        Arguments:
        access_list_name -- access-list name in string format
        """


        self.get_running_config()
        string_pos = self.get_string_position('ip access-list (extended|standard) ' + access_list_name + '\r\n')
        if not string_pos:
            raise AccessListNotExistError(msg_access_list_does_not_exist)
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
        access_list_entries = {}
        counter = 1
        prefix_len = len('access-list ' + access_list_number + ' ')
        string_pos = self.get_string_position('access-list ' + access_list_number + ' ' + '.*\r\n')
        if not string_pos:
            raise AccessListNotExistError(msg_access_list_does_not_exist)
        for pos in string_pos:
            access_list_entries[counter] = self.running_config['config'][pos[0] + prefix_len:pos[1]-2]
            counter = counter + 1
        
        return access_list_entries

    def parse_named_access_list(self,access_list_name):

        """
        Function is used to parse named access-list from running-config. It takes access-list name as an argument.
        
        Arguments:
        access_list_name -- access-list name in string format
        """


        self.get_running_config()
        access_list_entries = []
        string_pos = self.get_string_position('ip access-list (extended|standard) ' + access_list_name + '\r\n')
        if not string_pos:
            raise AccessListNotExistError(msg_access_list_does_not_exist)
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
        access_list_entries = self.get_numbered_access_list(access_list_number)
        try:
            for entry in entry_id_list:
                del access_list_entries[access_list_number]['entries'][int(entry)]
        except KeyError:
            raise AccessListEntryNotExistError(msg_access_list_entry_does_not_exist)

        try:
            command_response = self.execute_command('configure terminal')
        except CommandError:
            raise UnableToEnterConfigModeError(msg_unable_to_enter_config_mode)
        try:
            command_response = self.execute_command('no access-list ' + access_list_number)
        except CommandError:
            raise UnableToDeleteAccessListError(msg_unable_to_delete_access_list)

        if not len(entry_id_list) == 0:
            for key in sorted(access_list_entries[access_list_number]['entries'].keys()):
                try:
                    command_response = self.execute_command('access-list ' + access_list_number + ' ' + access_list_entries[access_list_number]['entries'][key])
                except CommandError:
                    raise UnableToConfigureEntryError(msg_unable_to_configure_entry)
        try:
            command_response = self.execute_command('exit')
        except CommandError:
            raise UnableToExitConfigModeError(msg_unable_to_exit_config_mode)


        self.get_running_config(force=True)
        return self.get_numbered_access_list(access_list_number)

    def delete_named_access_list_entry(self,access_list_name,entry_id_list):

        """

        """
       
        self.get_running_config()
        access_list_entries = self.get_named_access_list(access_list_name)
        try:
            for entry in entry_id_list:
                del access_list_entries[access_list_name]['entries'][int(entry)]
        except KeyError:
            raise AccessListEntryNotExistError(msg_access_list_entry_does_not_exist)


        try:
            command_response = self.execute_command('configure terminal')
        except CommandError:
            raise UnableToEnterConfigModeError(msg_unable_to_enter_config_mode)
        
        try:
            command_response = self.execute_command('no ip access-list ' + access_list_entries[access_list_name]['type'] + ' ' + access_list_name)
        except CommandError:
            raise UnableToDeleteAccessListError(msg_unable_to_delete_access_list)

        if not len(access_list_entries[access_list_name]['entries']) == 0 and not len(entry_id_list) == 0:
            try:
                command_response = self.execute_command('ip access-list ' + access_list_entries[access_list_name]['type'] + ' ' + access_list_name)
            except CommandError:
                raise UnableToApplyAccessListError(msg_unable_to_apply_access_list)
            for key in sorted(access_list_entries[access_list_name]['entries'].keys()):
                try:
                    command_response = self.execute_command(access_list_entries[access_list_name]['entries'][key])
                except CommandError:
                    raise UnableToConfigureEntryError(msg_unable_to_configure_entry)

        try:
            command_response = self.execute_command('end')
        except CommandError:
            raise UnableToExitConfigModeError(msg_unable_to_exit_config_mode)

        self.get_running_config(force=True)
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
        try:
            access_list_entries = self.get_numbered_access_list(access_list_number)
        except AccessListNotExistError:
            access_list_entries = {}
            access_list_entries[access_list_number] = {} 
            access_list_entries[access_list_number]['entries'] = {}
        try:
            int(entry_id)
        except:
            raise EntryNumberError(msg_entry_number)

        new_access_list_entries = {int(entry_id):access_list_entry}
        for key in access_list_entries[access_list_number]['entries'].keys():
            if key < int(entry_id):
                new_access_list_entries[key] = access_list_entries[access_list_number]['entries'][key]
            else:
                new_access_list_entries[key+1] = access_list_entries[access_list_number]['entries'][key]

        try:
            command_response = self.execute_command('configure terminal')
        except CommandError:
            raise UnableToEnterConfigModeError(msg_unable_to_enter_config_mode)
        try:
            command_response = self.execute_command('no access-list ' + access_list_number)
        except CommandError:
            raise UnableToDeleteAccessListError(msg_unable_to_delete_access_list)


        for key in sorted(new_access_list_entries.keys()):
            try:
                command_response = self.execute_command('access-list ' + access_list_number + ' ' + new_access_list_entries[key])
            except CommandError:
                raise AccessListSyntaxError(msg_access_list_syntax)
        try:
            command_response = self.execute_command('exit')
        except CommandError:
            raise UnableToExitConfigModeError(msg_unable_to_exit_config_mode)

        self.get_running_config(force=True)
        return self.get_numbered_access_list(access_list_number)

    def add_named_access_list_entry(self,access_list_name,entry_id,access_list_entry):

        """

        """

        self.get_running_config()
        try:
            access_list_entries = self.get_named_access_list(access_list_name)
        except AccessListNotExistError:
            access_list_entries = {}
            access_list_entries[access_list_name] = {} 
            access_list_entries[access_list_name]['entries'] = {}
            access_list_entries[access_list_name]['type'] = 'extended'
        try:
            int(entry_id)
        except:
            raise EntryNumberError(msg_entry_number)

        new_access_list_entries = {int(entry_id):access_list_entry}
        for key in access_list_entries[access_list_name]['entries'].keys():
            if key < int(entry_id):
                new_access_list_entries[key] = access_list_entries[access_list_name]['entries'][key]
            else:
                new_access_list_entries[key+1] = access_list_entries[access_list_name]['entries'][key]


        try:
            command_response = self.execute_command('configure terminal')
        except CommandError:
            raise UnableToEnterConfigModeError(msg_unable_to_enter_config_mode)
        try:
            command_response = self.execute_command('no ip access-list ' + access_list_entries[access_list_name]['type'] + ' ' + access_list_name)
        except CommandError:
            raise UnableToDeleteAccessListError(msg_unable_to_delete_access_list)
        

        try:
            command_response = self.execute_command('ip access-list ' + access_list_entries[access_list_name]['type'] + ' ' + access_list_name)
        except CommandError:
            raise UnableToApplyAccessListError(msg_unable_to_apply_access_list)
        for key in sorted(new_access_list_entries.keys()):
            try:
                command_response = self.execute_command(new_access_list_entries[key])
            except CommandError:
                raise AccessListSyntaxError(msg_access_list_syntax)
        try:
            command_response = self.execute_command('end')
        except CommandError:
            raise UnableToExitConfigModeError(msg_unable_to_exit_config_mode)

        self.get_running_config(force=True)
        return self.get_named_access_list(access_list_name)

    def move_access_list_entry(self,access_list,entry_id,new_position):

        """

        """
    
        try:
            int(access_list)
            return self.move_numbered_access_list_entry(access_list,entry_id,new_position)
        except ValueError:
            return self.move_named_access_list_entry(access_list,entry_id,new_position)  

    def move_numbered_access_list_entry(self,access_list_number,entry_id,new_position):

        """

        """

        self.get_running_config()
        access_list_entries = self.get_numbered_access_list(access_list_number)

        try:
            int(entry_id)
            int(new_position)
        except:
            raise EntryNumberError(msg_entry_number)

        try:
            moved_entry = {int(new_position): access_list_entries[access_list_number]['entries'][int(entry_id)]}
            del access_list_entries[access_list_number]['entries'][int(entry_id)]
        except KeyError:
            raise AccessListEntryNotExistError(msg_access_list_entry_does_not_exist)



        for key in sorted(access_list_entries[access_list_number]['entries'].keys()):
            if key > int(entry_id):

                access_list_entries[access_list_number]['entries'][key-1] = access_list_entries[access_list_number]['entries'][key]
                del(access_list_entries[access_list_number]['entries'][key])


        new_access_list_entries = moved_entry 

        for key in access_list_entries[access_list_number]['entries'].keys():
            if key < int(new_position):
                new_access_list_entries[key] = access_list_entries[access_list_number]['entries'][key]
            else:
                new_access_list_entries[key+1] = access_list_entries[access_list_number]['entries'][key]



        try:
            command_response = self.execute_command('configure terminal')
        except CommandError:
            raise UnableToEnterConfigModeError(msg_unable_to_enter_config_mode)
        try:
            command_response = self.execute_command('no access-list ' + access_list_number)
        except CommandError:
            raise UnableToDeleteAccessListError(msg_unable_to_delete_access_list)


        for key in sorted(new_access_list_entries.keys()):
            try:
                command_response = self.execute_command('access-list ' + access_list_number + ' ' + new_access_list_entries[key])
            except CommandError:
                raise AccessListSyntaxError(msg_access_list_syntax)
        try:
            command_response = self.execute_command('exit')
        except CommandError:
            raise UnableToExitConfigModeError(msg_unable_to_exit_config_mode)

        self.get_running_config(force=True)
        return self.get_numbered_access_list(access_list_number)


    def move_named_access_list_entry(self,access_list_name,entry_id,new_position):

        """

        """

        self.get_running_config()
        access_list_entries = self.get_named_access_list(access_list_name)

        try:
            int(entry_id)
            int(new_position)
        except:
            raise EntryNumberError(msg_entry_number)

        try:
            moved_entry = {int(new_position): access_list_entries[access_list_name]['entries'][int(entry_id)]}
            del access_list_entries[access_list_name]['entries'][int(entry_id)]
        except KeyError:
            raise AccessListEntryNotExistError(msg_access_list_entry_does_not_exist)



        for key in sorted(access_list_entries[access_list_name]['entries'].keys()):
            if key > int(entry_id):

                access_list_entries[access_list_name]['entries'][key-1] = access_list_entries[access_list_name]['entries'][key]
                del(access_list_entries[access_list_name]['entries'][key])


        new_access_list_entries = moved_entry
        for key in access_list_entries[access_list_name]['entries'].keys():
            if key < int(new_position):
                new_access_list_entries[key] = access_list_entries[access_list_name]['entries'][key]
            else:
                new_access_list_entries[key+1] = access_list_entries[access_list_name]['entries'][key]


        try:
            command_response = self.execute_command('configure terminal')
        except CommandError:
            raise UnableToEnterConfigModeError(msg_unable_to_enter_config_mode)
        try:
            command_response = self.execute_command('no ip access-list ' + access_list_entries[access_list_name]['type'] + ' ' + access_list_name)
        except CommandError:
            raise UnableToDeleteAccessListError(msg_unable_to_delete_access_list)

        try:
            command_response = self.execute_command('ip access-list ' + access_list_entries[access_list_name]['type'] + ' ' + access_list_name)
        except CommandError:
            raise UnableToApplyAccessListError(msg_unable_to_apply_access_list)
        for key in sorted(new_access_list_entries.keys()):
            try:
                command_response = self.execute_command(new_access_list_entries[key])
            except CommandError:
                raise AccessListSyntaxError(msg_access_list_syntax)
        try:
            command_response = self.execute_command('end')
        except CommandError:
            raise UnableToExitConfigModeError(msg_unable_to_exit_config_mode)

        self.get_running_config(force=True)
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
    group.add_argument('-mov', metavar=('acl_id','alc_entry_id','new_position'), nargs=3, help='Move access-list entry to new position')

    args = vars(parser.parse_args())
    if args['user'] == None:
        args['user'] = raw_input('Username: ')
    if args['pass'] == None:
        args['pass'] = getpass.getpass()
    credentials = {'username':args['user'],'password':args['pass']}


    access_lists = Access_lists(args['host'],credentials = credentials)
    try:
        access_lists.connect_to_device()
    except ConnectionError:
        print msg_unable_to_connect
        sys.exit()
    except AuthenticationError:
        print msg_authentication_failed
        sys.exit()


    
    if args['list'] == True:
        try:
            function_response = access_lists.get_list_of_all_access_lists()
            print json.dumps(function_response['acls'], indent=4)
        except RunningConfigError:
            print msg_running_config_failed
            sys.exit()
    elif args['acl'] != None:
        try:
            access_list_value = access_lists.get_access_list(args['acl'])
            print json.dumps(access_list_value, indent=4)
        except RunningConfigError:
            print msg_running_config_failed
        except NumberedOutOfRangeError:
            print msg_numbered_out_of_range
        except AccessListNotExistError:
            print msg_access_list_does_not_exist
    elif args['del'] != None:
        try:
            access_list_value = access_lists.delete_access_list_entry(args['del'][0],args['del'][1:])
            print json.dumps(access_list_value, indent=4)
        except RunningConfigError:
            print msg_running_config_failed
        except AccessListNotExistError:
            print msg_access_list_does_not_exist
        except AccessListEntryNotExistError:
            print msg_access_list_entry_does_not_exist
        except UnableToEnterConfigModeError:
            print msg_unable_to_enter_config_mode
        except UnableToDeleteAccessListError:
            print msg_unable_to_delete_access_list
        except UnableToConfigureEntryError:
            print msg_unable_to_configure_entry
        except UnableToExitConfigModeError:
            print msg_unable_to_exit_config_mode
        except UnableToApplyAccessListError:
            print msg_unable_to_apply_access_list
        except NumberedOutOfRangeError:
            print msg_numbered_out_of_range
        except UnableToDeleteAccessListError:
            print msg_unable_to_apply_access_list
    elif args['add'] != None:
        try:
            access_list_value = access_lists.add_access_list_entry(args['add'][0],args['add'][1],args['add'][2])
            print json.dumps(access_list_value, indent=4)
        except RunningConfigError:
            print msg_running_config_failed
        except NumberedOutOfRangeError:
            print msg_numbered_out_of_range
        except AccessListNotExistError:
            print msg_access_list_does_not_exist
        except EntryNumberError:
            print msg_entry_number
        except UnableToEnterConfigModeError:
            print msg_unable_to_enter_config_mode
        except UnableToDeleteAccessListError:
            print msg_unable_to_delete_access_list
        except AccessListSyntaxError:
            print msg_access_list_syntax
        except UnableToExitConfigModeError:
            print msg_unable_to_exit_config_mode
        except UnableToApplyAccessListError:
            print msg_unable_to_apply_access_list
    elif args['mov'] != None:
        try:
            access_list_value = access_lists.move_access_list_entry(args['mov'][0],args['mov'][1],args['mov'][2])
            print json.dumps(access_list_value, indent=4)
        except RunningConfigError:
            print msg_running_config_failed
        except NumberedOutOfRangeError:
            print msg_numbered_out_of_range
        except AccessListNotExistError:
            print msg_access_list_does_not_exist
        except EntryNumberError:
            print msg_entry_number
        except UnableToEnterConfigModeError:
            print msg_unable_to_enter_config_mode
        except UnableToDeleteAccessListError:
            print msg_unable_to_delete_access_list
        except AccessListSyntaxError:
            print msg_access_list_syntax
        except UnableToExitConfigModeError:
            print msg_unable_to_exit_config_mode
        except UnableToApplyAccessListError:
            print msg_unable_to_apply_access_list
        except AccessListEntryNotExistError:
            print msg_access_list_entry_does_not_exist
    else:
        try:
            access_list_value = access_lists.get_all_access_lists()
            print json.dumps(access_list_value['acls'], indent=4)
        except RunningConfigError:
            print msg_running_config_failed
        except NumberedOutOfRangeError:
            print msg_numbered_out_of_range
        except AccessListNotExistError:
            print msg_access_list_does_not_exist

    access_lists.disconnect_device()

