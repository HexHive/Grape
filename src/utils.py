from config import *

import yaml
import json 
import subprocess
import logging
import os
from datetime import datetime
import multiprocessing
import sys
import re 




timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

global_json_list = []

black_namespace = {
    'ui' : ['std', 'base'],
    'js' : []
}

black_func_name = {
    'ui' : ['RunTask', 'RemoveObserver', 'AddObserver', 
            'Execute', 'Dispatch', 'Get', 'Find', 'Save', 
            'ReadBool', 'EndReadData'],
    'js' : []

}

black_obj_name = {
    'ui' : [],
    'js' : ['Node', 'Color']

}


def is_upper_camel_case(s: str) -> int:
    """
        Chrome's member function name is suppose to be upper camel case
    """
    pattern = r'^[A-Z][a-z]+(?:[A-Z][a-z]*)*$'
    if bool(re.match(pattern, s)):
        n_upper = 0
        for c in s:
            if c.isupper():
                n_upper += 1
        return n_upper
    else:
        return 0


def is_black_list_func(func_name: str, bug_variant: str) -> bool :
    if len(black_func_name[bug_variant]) == 0:
        return False
    if func_name.islower():
        return True
    for bnamespace in black_namespace[bug_variant]:
        if func_name.startswith(bnamespace):
            return True
    if is_upper_camel_case(clean_func_name(func_name)) <= 1:
        return True
    for bfunc in black_func_name[bug_variant]:
        if clean_func_name(func_name).startswith(bfunc):
            return True
    return False    

def is_black_list_obj(func_name: str, bug_variant: str) -> bool:
    if len(black_obj_name[bug_variant]) == 0:
        return False
    for bobj in black_obj_name[bug_variant]:
        if better_func_name(func_name).find(bobj) != -1:
            return True
    return False   

def clean_func_name(func_name: str) -> str:
    """
        only get the member function name, 
        e.g. for obj->Member(), we extract Member
    """
    prefix_list = ['->', '.', '::', ' ']
    for prefix in prefix_list:
        if func_name.rfind(prefix) != -1:
            func_name = func_name[func_name.rfind(prefix) + len(prefix):]
    return func_name

def better_func_name(func_name: str) -> str:
    """
        abstract context might change class::Member to "class Member",
        we change it back
    """
    func_name = func_name.replace('->->', '->')
    return func_name.replace(' ', '::')

def object_caller_name(func_name: str) -> str:
    """
        For pdfium js issue, the caller type can be used to filter out 
        the FPs, as only xfa related stuff will invoke js
        return the caller obj, 
        e.g. for m_pFormFiller->OnFormat, return m_pFormFiller
    """
    dot_index = func_name.rfind('.')
    arrow_index = func_name.rfind('->')
    if dot_index == -1 and arrow_index == -1:
        return ''
    elif arrow_index > dot_index:
        strip_name = func_name.split('->')[-2]
        if strip_name.rfind('.') != -1:
            return strip_name.split('.')[-1]
        else:
            return strip_name
    else:
        strip_name = func_name.split('.')[-2]
        if strip_name.rfind('->') != -1:
            return strip_name.split('->')[-1]
        else:
            return strip_name

# unittest
# object_caller_name('abc.def->OnFormat')
# object_caller_name('abc.def.OnFormat')
# object_caller_name('abc->def->OnFormat')
# object_caller_name('abc->def.OnFormat')
# object_caller_name('abc.OnFormat')

def noprefix_path(abs_path: str) -> str:
    """
        convert absolute path to relative path
        e.g. /home/user/workspace/chrome/download/src/rel/path to rel/path
    """
    if abs_path.rfind('src/') == -1:
        return abs_path
    return abs_path[abs_path.rfind('src/') + len('src/'):]

# exclude third_party for UI

semgrep_ignore_list = [
  '*_tests.h',
  '*_tests.cc',
  '*_unittests.cc',
  '*_test.h',
  '*_test.cc',
  '*_unittest.cc',
  '*_browsertest.cc',
  '*_test_*.cc',
  '*.test.ts',
  '*test*.ts'
]

def prepare_semgrep_ignore():
    ignore_file = f"{os.getcwd()}/.semgrepignore"
    if os.path.exists(ignore_file):
        return
    with open(ignore_file, 'w') as f:
        f.write('\n'.join(semgrep_ignore_list))


def get_tmp_stamp() -> str:
    """
        return: unique timestamp for tmpfile
    """
    return timestamp

def get_logger(name: str):
    logger = logging.getLogger(name)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging_level())
    formatter = logging.Formatter('[%(asctime)s] - [%(name)s] %(message)s')
    handler.setFormatter(formatter)
    logger.setLevel(logging_level())
    logger.addHandler(handler)
    return logger

logger = get_logger(__name__)


def parse_item(bug_variant: str, item: dict):
    """
        return path, func_name, func_line
    """
    func_path = item['path']
    func_name = item['extra']['metavars'][get_keywords(bug_variant)]['abstract_content']
    func_line = [
        item['extra']['metavars'][get_keywords(bug_variant)]['start']['line'],
        item['extra']['metavars'][get_keywords(bug_variant)]['start']['col'],
        item['extra']['metavars'][get_keywords(bug_variant)]['end']['line'],
        item['extra']['metavars'][get_keywords(bug_variant)]['end']['col']
    ]
    return func_path, func_name, func_line


def count_vuln_num(unsafe_violation: dict) -> int:
    vuln_num = 0
    for func_src in unsafe_violation:
        vuln_num += len(unsafe_violation[func_src])
    return vuln_num

def clean_empty_func(unsafe_violation: dict) -> dict:
    clean_unsafe_violation = dict()
    for func_src in unsafe_violation:
        if len(unsafe_violation[func_src]) != 0:
            clean_unsafe_violation[func_src] = unsafe_violation[func_src]
    return clean_unsafe_violation

# Helper Functions / Classes
class BlockStyleDumper(yaml.Dumper):
    """
      avoid re-sanitize the yaml format
    """
    def represent_scalar(self, tag, value, style=None):
        # If the value contains newlines, represent it as a block scalar
        if '\n' in value:
            style = '|'
        return super().represent_scalar(tag, value, style)

def has_defination(func_name: str, temp_path: str, source_file_path: str) -> bool: 
    """
        Run Semgrep to verify if there is defination in same file
        e.g. for violation function RespondToReader, in same source file 
        there is AndroidUsbSocket::RespondToReader, so we only need to scan the source file
    """
    base_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

    helper_rule_path = f"{base_dir}/config/help/defination.yaml"
    temp_rule_path = f"{temp_path}/temp/defination-{func_name}-{source_file_path.replace('/', '.')}.yaml"
    # temp_json_path = f"{temp_path}/temp/defination-{func_name}.json"

    create_tmp_dir(temp_rule_path)

    with open(helper_rule_path) as f:
        config_dict = yaml.safe_load(f)
    
    regex_func = f"^([A-Za-z_]+::)?{func_name}$"
    new_metavariable_regex = {
        'metavariable-regex': {
            'metavariable': '$FUNC_NAME',
            'regex': f'{regex_func}'
        }
    }
    config_dict['rules'][0]['patterns'].append(new_metavariable_regex)
    
    with open(temp_rule_path, 'w') as f:
        yaml.dump(config_dict, f, default_flow_style=False, Dumper=BlockStyleDumper)
    
    logger.debug(f"We dump the temporary config at {temp_rule_path}")

    data_raw = run_semgrep_query_single(temp_rule_path, source_file_path, '', use_stdout = True)
    data = json.loads(data_raw)

    logger.debug (f"size of the results is {len(data['results'])}")

    if len(data['results']) == 1:
        return True
    
    return False


def get_file_list(func_name: str, repo_path: str) -> list:
    """
        Get a list of the file that has func_name, 
        reduce workload of semgrep, as its much expensive
    """
    cmd = [
            'grep', '-rl', '--include=*.cc', '--include=*.cpp',
            '--exclude=*test.cc', '--exclude=*_test*.cc', '--exclude=*_unittest.cc', 
            '--exclude=*test.cpp', '--exclude=*_test*.cpp', '--exclude=*_unittest.cpp', 
            func_name, repo_path
        ]

    try:
        # Run the grep command and capture the output
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Split the output by lines to get the list of files
        file_list = result.stdout.splitlines()
        
        return file_list

    except subprocess.CalledProcessError as e:
        logger.error(f"Error running grep: {e.stderr}")
        exit (0)

def exclude_file_list(func_name: str, temp_path:str, src_path_list: list, violation_path: str)-> list:
    """
        If the file already have defination, we don't need it, as the callsite in the file 
        is not calling the FREE_FUNC
    """
    new_path_list = list()
    new_path_list.append(violation_path)

    for src in src_path_list:
        if src == violation_path:
            continue
        if not has_defination(func_name, temp_path, src):
            new_path_list.append(src)
    
    return new_path_list

def run_semgrep_lists(src_path_list: list, rule_file: str, 
                      temp_path: str, json_output: str, 
                      clean_vfunc_name: str) -> str:
    """
        Run semgrep query on a list of files
    """
    final_output = dict()

    # src_id = 0
    for src in src_path_list:

        data_raw = run_semgrep_query_single(rule_file, src, '', use_stdout = True)
        data = json.loads(data_raw)
        
        if final_output == dict():
            final_output = data 
        else:
            final_output['results'] +=  data['results']
    
    with open(json_output, 'w') as f:
        json.dump(final_output, f)



def create_tmp_dir(tmp_file_path: str):
    dir_path = os.path.dirname(tmp_file_path) 
    if not os.path.isdir(dir_path):
        os.makedirs(dir_path, exist_ok=True)

def run_semgrep_query_single(rule_file: str, repo_path: str, 
                             json_output: str = '', 
                             use_stdout: bool = False) -> str:
    """
        Single thread version run_semgrep_query
    """
    return run_semgrep_query(rule_file, repo_path, json_output, use_stdout, jobs = 1)

def run_semgrep_query(rule_file: str, repo_path: str, 
                      json_output: str = '', use_stdout: bool = False,
                      jobs: int = 0) -> str:
    """
    Runs the Semgrep command with the specified rule file and repository path.
    
    :param rule_file: Path to the YAML rule file for Semgrep.
    :param repo_path: Path to the repository directory on which Semgrep should be run.
    :return: json_output path or stdout of the Semgrep command if successful.
    :raises RuntimeError: If the Semgrep command fails.
    """
    # if os.path.basename(json_output) not in global_json_list:
    #     global_json_list.append(os.path.basename(json_output))
    # else:
    #     logger.error (f"conflict json_output name {json_output}")
    #     exit(0)
    try:
        cmd = ['semgrep', '-f', rule_file]
        
        if json_output != '':
            if os.path.exists(json_output):
                return json_output
            if not use_stdout:
                cmd.append(f'--json-output={json_output}')                
        elif use_stdout:
            cmd.append(f'--json')

        if jobs == 0:
            cmd.append(f'--jobs={multiprocessing.cpu_count()}')
        else:
            cmd.append(f'--jobs={jobs}')

        # no data collection
        cmd.append('--metrics=off')
        
        cmd.append(repo_path)
        
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if json_output != '':
            logger.debug(f"Execute one Query, output at {json_output}")
            return json_output
        else :
            logger.debug(f"Execute one Query, stdout output")
            return result.stdout

    except subprocess.CalledProcessError as e:
        error_msg = f"Semgrep command failed with exit code {e.returncode}. Error output:\n{e.stderr}"
        logger.error(error_msg)
        raise RuntimeError(error_msg)

    except FileNotFoundError:
        error_msg = f"Semgrep command not found. Please ensure Semgrep is installed and available in your PATH."
        raise RuntimeError(error_msg)

