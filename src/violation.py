from utils import *

import logging
import os 
import argparse
import json
import sys

logger = get_logger(__name__)


def parse_violation_function(result_path: str, bug_variant: str) -> dict:
  """
    return a deduplicated unique violation function list
  """
  with open(result_path) as f:
    violation_results = json.load(f)
  
  violation_func_list = dict()
  black_listed_lines = dict()

  # use if we only consider member function name
  # e.g. obj1->SetRotation is equal to obj2.SetRotation now, so 
  # for performance reason, we only run it once
  unique_func_list = list()
  
  for item in violation_results['results']:
    func_src, func_name, func_line = parse_item(bug_variant, item)
    if func_src not in violation_func_list:
      violation_func_list[func_src] = dict()
    
    if better_func_name(func_name) in violation_func_list[func_src] or \
       clean_func_name(func_name) in unique_func_list: # only if we use member function name
      logger.debug(f"{better_func_name(func_name)} duplicate!")
      continue
        
    if is_black_list_func(func_name, bug_variant):
      logger.debug (f'skip black listed {better_func_name(func_name)}!')
      if func_src not in black_listed_lines:
        black_listed_lines[func_src] = list()
      black_listed_lines[func_src].append(func_line[0])
      continue
    
    # FUNC1($BLACK_LIST(), ...), skip them 
    if func_src in black_listed_lines and \
       func_line[0] in black_listed_lines[func_src]:
      logger.debug (f'skip black listed {better_func_name(func_name)}!')
      continue 
    
    # duplicate FUNC1(FUNC2(), arg...), we opt for earlier FUNC1
    skip_duplicate = 0
    # deep copy
    func_lst_copy = list(violation_func_list[func_src].keys())
    for prior_func in func_lst_copy:
      prior_line = violation_func_list[func_src][prior_func]
      if func_line[0] == prior_line[0]:
        # if start_col equal, duplicate
        if func_line[1] > prior_line[1]:
          # prior_line contain func_line
          skip_duplicate = 1
          logger.debug (f'skip duplicate {better_func_name(func_name)}, whose addr {func_line} inside {prior_line}!')
          break
        else:
          del violation_func_list[func_src][prior_func]
          logger.debug (f'remove duplicate {prior_func}, whose addr {prior_line} inside {func_line}!')
    if skip_duplicate == 0:
      logger.debug (f"add new function {better_func_name(func_name)}, {func_line}")
      unique_func_list.append(clean_func_name(func_name))
      violation_func_list[func_src][better_func_name(func_name)] = func_line
  return violation_func_list
  


def get_violation_list(bug_variant: str, repo_path: str, tmp_dir: str) -> dict:
  bug_variant_config = get_bug_variant_config()
  if bug_variant not in bug_variant_config:
    logger.error (f"Error: {bug_variant} not defined!")
    exit(0)
  
  base_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
  rule_file = f"{base_dir}/config/violation/{bug_variant}/{bug_variant}.yaml"
  logger.info (f"Processing Violations Functions from {bug_variant}/{bug_variant}.yaml...")

  result_path = f"{tmp_dir}/violation/{bug_variant}-{get_tmp_stamp()}.json"

  create_tmp_dir(result_path)

  run_semgrep_query(rule_file, repo_path, result_path)
  
  violation_func_list = parse_violation_function(result_path, bug_variant)
  
  return violation_func_list


# export function
def get_violation_only(bug_variant: str, repo_path: str, temp_path: str):
  """
    in case the violation function is fixed
  """
  rule_file = f"{get_base_dir()}/config/violation/{bug_variant}/{bug_variant}.yaml"
  result_path = f"{temp_path}/violation/{bug_variant}-{get_tmp_stamp()}.json"
  
  create_tmp_dir(result_path)
  run_semgrep_query(rule_file, repo_path, result_path)
  
  with open(result_path) as f:
    data = json.load(f)
  
  abuse_list = dict()
  for item in data['results']:
    func_path, func_name, func_line = parse_item(bug_variant, item)
    if 'test' in func_name or \
       'temp' in func_name:
      continue
    if func_path not in abuse_list:
      abuse_list[func_path] = dict()
    abuse_list[func_path][func_name] = func_line

  
  json_result_path = f"{temp_path}/result/{bug_variant}/all-abuse.json"
  create_tmp_dir(json_result_path)

  with open(json_result_path, 'w') as f:
    json.dump(abuse_list, f)
  
  return count_vuln_num(abuse_list)
  

# testing functions from now on
def parse_arguments():
    parser = argparse.ArgumentParser(description="Process repository path and bug variant.")
    parser.add_argument('-r', '--repo_path', required=True, help="Path to the repository")
    parser.add_argument('-t', '--temp_path', required=True, help="Path to the temp dir")
    parser.add_argument('bug_variant', choices=get_bug_variant_config().keys(), 
                        help="Bug variant to process (e.g., 'ui', 'js')")    
    args = parser.parse_args()
    
    return args

if __name__ == "__main__":
    # Parse command-line arguments
    args = parse_arguments()
    
    # Call the function to get the violation list based on the parsed arguments
    violation_func_list = get_violation_list(args.bug_variant, args.repo_path, args.temp_path)

    n_violation_func = 0

    for src in violation_func_list:
      for func_name in violation_func_list[src]:
        print (f"{src}, {func_name}, {violation_func_list[src][func_name][0]}")
        n_violation_func += 1
    
    logger.debug (f"In total, we detect {n_violation_func} violation functions:")
