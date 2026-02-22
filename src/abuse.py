from utils import *
from config import *

import logging
import json 
import yaml
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed


logger = get_logger(__name__)

def generate_regex(violation_func: str) -> str:
    # Check if '.', ':' or '->' is present
    dot_index = violation_func.rfind('.')
    arrow_index = violation_func.rfind('->')
    colon_index = violation_func.rfind(':')

    clean_vfunc = clean_func_name(violation_func)
    
    # If both '.' and '->' exist, choose the rightmost one
    if dot_index != -1 or arrow_index != -1:
        if dot_index > arrow_index:
            # Match bbb.violation_func
            regex_func = f"^\\w+\\.{clean_vfunc}$"
        else:
            # Match aaa->violation_func
            regex_func = f"^\\w+->{clean_vfunc}$"
    elif colon_index != -1:
        regex_func = f"^\\w+::{clean_vfunc}$"
    else:  
        # If neither '.' nor '->' exists, match violation_func only
        regex_func = f"^{clean_vfunc}$"
    
    return regex_func

def generate_new_yaml(orig_path: str, output_path: str, violation_func: str):
  """
    write the modified config to output_path
  """
  with open(orig_path) as f:
    config_dict = yaml.safe_load(f)
  
  regex_func = generate_regex(violation_func)
  # regex_func = f"(\w+(\.|->))?{violation_func}(?!\w)"

  new_metavariable_regex = {
    'metavariable-regex': {
        'metavariable': '$FREE_FUNC',
        'regex': f'{regex_func}'
    }
  }

  config_dict['rules'][0]['patterns'].append(new_metavariable_regex)
  
  with open(output_path, 'w') as f:
      yaml.dump(config_dict, f, default_flow_style=False, Dumper=BlockStyleDumper)
  
  logger.debug(f"We dump the temporary config at {output_path}")

def parse_violation_callsite(bug_variant:str, result_path: str) -> dict:
  """
    all violation function callsite, use source and line as key
    as it's very likely there are duplicate function names on 
    different callsites
  """
  with open(result_path) as f:
    violation_results = json.load(f)
  
  violation_func_list = dict()
  
  for item in violation_results['results']:
    func_name = item['extra']['metavars']['$FREE_FUNC']['abstract_content']
    func_line = '%s,%s' % (
        item['extra']['metavars']['$FREE_FUNC']['start']['line'],
        item['extra']['metavars']['$FREE_FUNC']['end']['line']
    )
    func_src = item['path']
    if func_src not in violation_func_list:
      violation_func_list[func_src] = dict()
    
    # if is_black_list_obj(func_name, bug_variant):
      # logger.debug(f'Skipping blacklisted {better_func_name(func_name)}...')
    # else:
    violation_func_list[func_src][func_line] = func_name.replace('->->', '->')
  
  return violation_func_list

def merge_safe_violations(tmp_safe_violations: dict, safe_violations: dict) -> dict:
  for func_src in tmp_safe_violations:
    if func_src not in safe_violations:
      safe_violations[func_src] = dict()
    for func_line in tmp_safe_violations[func_src]:
      if func_line not in safe_violations[func_src]:
        safe_violations[func_src][func_line] = tmp_safe_violations[func_src][func_line]
  return safe_violations

def get_unsafe_violations(safe_violations: dict, all_violations: dict) -> dict:
  unsafe_violations = dict()
  for func_src in all_violations:
    if func_src not in safe_violations:
      unsafe_violations[func_src] = all_violations[func_src]
      continue
    unsafe_violations[func_src] = dict()
    for func_line in all_violations[func_src]:
      if func_line not in safe_violations[func_src]:
        unsafe_violations[func_src][func_line] = all_violations[func_src][func_line]
  return unsafe_violations

def get_safe_violation_list(bug_variant: str, 
                  repo_path: str, temp_path: str, 
                  violation_path: str, violate_func_name: str,
                  only_fast_scan: bool) -> dict:

  safe_violations = dict()
  clean_vfunc_name = clean_func_name(violate_func_name)

  for safe_template_name in get_safe_abuse_list(bug_variant):

    template_rule_file = f"{get_base_dir()}/config/abuse/{bug_variant}/{safe_template_name}"

    # debugging propose
    logger.debug (f"Processing Safe Violations from {bug_variant}/{safe_template_name}...")
    violate_output_name = safe_template_name.replace('yaml', 'json')
    temp_rule_file = f"{temp_path}/abuse/{bug_variant}-{get_tmp_stamp()}-{clean_vfunc_name}-{safe_template_name}"

    create_tmp_dir(temp_rule_file)
    generate_new_yaml(template_rule_file, temp_rule_file, violate_func_name)

    json_result_path = f"{temp_path}/abuse/{bug_variant}-{get_tmp_stamp()}-{clean_vfunc_name}-{violate_output_name}"
    if only_fast_scan:
      run_semgrep_query_single(temp_rule_file, violation_path, json_result_path)
    else:
      src_path_list = get_file_list(clean_vfunc_name, repo_path)
      src_path_list = exclude_file_list(clean_vfunc_name, temp_path, src_path_list, violation_path)
      run_semgrep_lists(src_path_list, temp_rule_file, temp_path, json_result_path, clean_vfunc_name)
      # run_semgrep_query(temp_rule_file, repo_path, json_result_path)

    tmp_safe_violations = parse_violation_callsite(bug_variant, json_result_path)
    safe_violations = merge_safe_violations(tmp_safe_violations, safe_violations)

  return safe_violations


def get_all_violation_list(bug_variant: str, 
                repo_path: str, temp_path: str, 
                violation_path: str, violate_func_name: str,
                only_fast_scan: bool) -> dict:

  template_rule_file = f"{get_base_dir()}/config/abuse/{bug_variant}/all_template.yaml"
  clean_vfunc_name = clean_func_name(violate_func_name)

  logger.debug (f"Processing All Violations Callsites from {bug_variant}/all_template.yaml...")

  temp_rule_file = f"{temp_path}/abuse/{bug_variant}-{get_tmp_stamp()}-{clean_vfunc_name}-all.yaml"
  create_tmp_dir(temp_rule_file)

  if bug_variant == 'js':
    # js only need obj->$FREE_FUNC, so we don't need generate_regex to include ->/. in regex
    generate_new_yaml(template_rule_file, temp_rule_file, clean_func_name(violate_func_name))
  else:
    generate_new_yaml(template_rule_file, temp_rule_file, violate_func_name)
  json_result_path = f"{temp_path}/abuse/{bug_variant}-{get_tmp_stamp()}-{clean_vfunc_name}-all.json"

  if only_fast_scan:
    run_semgrep_query_single(temp_rule_file, violation_path, json_result_path)
  else:
    src_path_list = get_file_list(clean_vfunc_name, repo_path)
    src_path_list = exclude_file_list(clean_vfunc_name, temp_path, src_path_list, violation_path)
    run_semgrep_lists(src_path_list, temp_rule_file, temp_path, json_result_path, clean_func_name)
    # run_semgrep_query(temp_rule_file, repo_path, json_result_path)

  return parse_violation_callsite(bug_variant, json_result_path)


def get_func_abuses(bug_variant: str, repo_path: str, 
                    temp_path: str, violation_path: str, 
                    violate_func_name: str) -> int:
  """
    get all potential vulnerbilities for one function
  """
  only_fast_scan = has_defination(clean_func_name(violate_func_name), temp_path, violation_path)
  if is_fast_scan():
    only_fast_scan = True
  safe_violation_list = get_safe_violation_list(bug_variant, 
                        repo_path, temp_path, violation_path, 
                        violate_func_name, only_fast_scan)

  all_violation_list = get_all_violation_list(bug_variant, 
                        repo_path, temp_path, violation_path, 
                        violate_func_name, only_fast_scan)
  
  unsafe_violation_list = get_unsafe_violations(safe_violation_list, all_violation_list)

  json_result_path = f"{temp_path}/result/{bug_variant}/{clean_func_name(violate_func_name)}-abuse.json"
  create_tmp_dir(json_result_path)

  vuln_num = count_vuln_num(unsafe_violation_list)

  if vuln_num > 0:
    with open(json_result_path, 'w') as f:
      json.dump(clean_empty_func(unsafe_violation_list), f)
  
  return vuln_num

# export function
def get_all_abuse(bug_variant: str, repo_path: str, temp_path: str, violate_func_list: dict):
  """
    get all potential vulnerbilities for whole function list (multi-thread)
  """
  candidate_cur = 0
  vuln_num = 0
  candidate_num = count_vuln_num(violate_func_list)
  nproc = multiprocessing.cpu_count() # max_workers=nproc
  with ThreadPoolExecutor(max_workers=nproc) as executor:
    futures = []
        
    # Iterate through the function list and submit tasks to the thread pool
    for src in violate_func_list:
      for func_name in violate_func_list[src]:
        
        # Submit the new task
        futures.append(executor.submit(get_func_abuses, bug_variant, repo_path, temp_path, src, func_name))

    # Collect results from all futures as they complete
    for future in as_completed(futures):
      try:
        vuln_num += future.result() 
        candidate_cur += 1 
        logger.info(f"Finished violation function : {candidate_cur} / {candidate_num}")

      except Exception as e:
        logger.error(f"Error processing function: {e}")

  return vuln_num


# export function
def get_abuse_only(bug_variant: str, repo_path: str, temp_path: str):
  """
    in case the violation function is fixed
  """
  rule_file = f"{get_base_dir()}/config/abuse/{bug_variant}/all_template.yaml"
  result_path = f"{temp_path}/abuse/{bug_variant}-{get_tmp_stamp()}.json"
  
  create_tmp_dir(result_path)
  run_semgrep_query(rule_file, repo_path, result_path)
  
  with open(result_path) as f:
    data = json.load(f)
  
  abuse_list = dict()
  for item in data['results']:
    func_path, func_name, func_line = parse_item(bug_variant, item)
    if func_path not in abuse_list:
      abuse_list[func_path] = dict()
    abuse_list[func_path][func_name] = func_line
  
  json_result_path = f"{temp_path}/result/{bug_variant}/all-abuse.json"
  create_tmp_dir(json_result_path)

  with open(json_result_path, 'w') as f:
    json.dump(abuse_list, f)
  
  return count_vuln_num(abuse_list)
  

def get_all_abuse_single(bug_variant: str, repo_path: str, temp_path: str, violate_func_list: dict):
  """
    get all potential vulnerbilities for whole function list (single-thread, debug)
  """
  candidate_cur = 0
  vuln_num = 0
  candidate_num = count_vuln_num(violate_func_list)
  for src in violate_func_list:
    for func_name in violate_func_list[src]:
      candidate_cur += 1 
      vuln_num += get_func_abuses(bug_variant, repo_path, temp_path, src, func_name)
      logger.info(f"Finished violation function : {candidate_cur} / {candidate_num}")
  return vuln_num

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
    # safe_violation_list = get_safe_violation_list(args.bug_variant, args.repo_path, args.temp_path)
    get_func_abuses(args.bug_variant, args.repo_path, args.temp_path, 'SetFullscreen')


