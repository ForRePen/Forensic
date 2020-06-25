import volatility.plugins.taskmods as taskmods
import volatility.plugins.common as common
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.conf as conf
import volatility.registry as registry
import volatility.utils as utils
import volatility.win32 as win32

import jellyfish


class Process(object):
    """Class to abstract Volatility Process object API"""
 
    def __init__(self, process):
        self._pid = process.UniqueProcessId
        self._ppid = process.InheritedFromUniqueProcessId
        self._parameters = process.Peb.ProcessParameters
        self._commandline = process.Peb.ProcessParameters.CommandLine
        self._session_id = process.SessionId
        self._image_filename = str(process.ImageFileName)
        self._image_path = process.Peb.ProcessParameters.ImagePathName
        self._create_time = process.CreateTime

    def get_pid(self):
        return self._pid

    def get_ppid(self):
        return self._ppid

    def get_parameters(self):
        return self._parameters

    def get_commandline(self):
        return self._commandline

    def get_session_id(self):
        return self._session_id

    def get_image_filename(self):
        return self._image_filename

    def get_image_path(self):
        return self._image_path

    def get_create_time(self):
        return self._create_time


class ProcessHunt(common.AbstractWindowsCommand):
    """Hunt for suspicious Windows process"""

    def calculate(self):
        
        processes = list()
        suspicious_processes = list()
        process_numbers = dict()

        addr_space = utils.load_as(self._config)
        for process in win32.tasks.pslist(addr_space):
            abstract_process = Process(process)

            processes.append(abstract_process)

            if abstract_process.get_image_filename().lower() not in process_numbers:
                process_numbers[abstract_process.get_image_filename().lower()] = 1
            else:
                process_numbers[abstract_process.get_image_filename().lower()] += 1
            
        for process in processes:
            if process.get_parameters():
                self._check_process_imagepath(process, process.get_image_path(), suspicious_processes)

            self._check_process_genealogy(process, processes, suspicious_processes)
            self._check_process_renaming(process, suspicious_processes)
            self._check_process_number(process, process_numbers, suspicious_processes)

        return suspicious_processes

    def _check_process_genealogy(self, process, processes, suspicious_processes):
        """
        Compare process genealogy to ensure processes are spawn by legit parent processes
        """
        process_genealogy = {
            'svchost.exe': 'services.exe',
            'lsass.exe': 'wininit.exe',
            'services.exe': 'wininit.exe',
            'taskhost.exe': 'services.exe',
            'taskhostw.exe': 'svchost.exe',
            'smss.exe': 'System',
            'conhost.exe': 'csrss.exe',
        }

        process_name = process.get_image_filename()
        
        if process_name in process_genealogy:
            ppid = process.get_ppid()
            for other_process in processes:
                pid = other_process.get_ppid()
                if pid == ppid:
                    other_process_name = other_process.get_image_filename()
                    if other_process_name != process_genealogy[process_name]:
                        msg = '{0} process not attached to {1} process'.format(process_name, process_genealogy[process_name])
                        suspicious_processes.append((other_process, msg))

    def _check_process_imagepath(self, process, image_path, suspicious_processes):
        """
        Compare image path of process to known Windows path
        """
        process_imagepath = {
            'smss.exe': '\\SystemRoot\\System32\\smss.exe',
            'csrss.exe': 'C:\\Windows\\system32\\csrss.exe',
            'wininit.exe': 'C:\\Windows\\system32\\wininit.exe',
            'services.exe': 'C:\\Windows\\system32\\services.exe',
            'lsass.exe': 'C:\\Windows\\system32\\lsass.exe',
            'lsm.exe': 'C:\\Windows\\system32\\lsm.exe',
            'svchost.exe': 'C:\\Windows\\system32\\svchost.exe',
            'explorer.exe': 'C:\\Windows\\explorer.exe',
            'conhost.exe': 'C:\\Windows\\system32\\conhost.exe',
            'cmd.exe': 'C:\\Windows\\system32\\cmd.exe',
        }

        if process in process_imagepath:
            if image_path.lower() != process_imagepath[process].lower():
                msg = '{0} process is from {1} but should be from {2}'.format(process, image_path, process_imagepath[process])
                suspicious_processes.append((process, msg))

    def _check_process_renaming(self, process, suspicious_processes):
        """
        Check process renaming as svchosts for scvhost or lsasss for lsass
        List of process to check should be upgraded to cover more known/used processes
        """
        known_processes = [ 'smss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'lsm.exe', 'svchost.exe',
                              'explorer.exe', 'conhost.exe', 'lsm.exe', 'cmd.exe', 'powershell.exe']

        for known_process in known_processes:
            if jellyfish.damerau_levenshtein_distance(known_process.decode(), process.get_image_filename().decode()) == 1:
                msg = '{0} process is suspicious as it looks like {1}'.format(process.get_image_filename(), known_process)
                suspicious_processes.append((process, msg))

    def _check_process_number(self, process, process_numbers, suspicious_processes):
        """
        Check number of known Windows processes
        """
        known_process_numbers = {
            'smss.exe': 1,
            'csrss.exe': 1, #Per session
            'services.exe': 1,
            'lsass.exe': 1,
            'system': 1,
        }

        for process_name in process_numbers:
            if process_name.lower() in known_process_numbers and process_numbers[process.get_image_filename().lower()] != known_process_numbers[process_name.lower()]:
                msg = '{0} process is suspicious as it is spawned {1} times but should be spawned {2} times'.format(process_name, process_numbers[process_name.lower()], known_process_numbers[process_name.lower()])
                suspicious_processes.append((process, msg))

    def _check_session_number(self, process, suspicious_processes):
        """
        Check Session ID of known Windows processes
        """
        known_process_session = {
            'smss.exe': 0,
            'csrss.exe': 0,
            'wininit.exe': 0,
            'services.exe': 0,
            'lsass.exe': 0,
            'svchost.exe': 0,
            'lsm.exe': 0,
            'winlogon.exe': 1,
        }

        if process.get_session_id() != known_process_session[process.get_image_filename().lower()]:
                msg = '{0} process is suspicious as it is spawned with session ID {1} but should be spawned with session ID {2}'.format(process.get_image_filename(), process.get_session_id(), known_process_session[process.get_image_filename().lower()])
                suspicious_processes.append((process, msg))

    def render_text(self, outfd, data):
        tree = dict()

        outfd.write('PID\t PPID\t Create Time\t\t\t Process\t Message\n')

        for suspicious_task in data:
            outfd.write('{0}\t {1}\t {2}\t {3}\t {4}\n'.format(suspicious_task[0].get_pid(), suspicious_task[0].get_ppid(), suspicious_task[0].get_create_time(), suspicious_task[0].get_image_filename(), suspicious_task[1]))



