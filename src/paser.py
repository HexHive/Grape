"""
  Parse the output report to make it more readable
"""

import json 
from utils import *

logger = get_logger(__name__)

def match_false_positive(bug_variant, func_name, path, num):
  """
    Return if its FP
  """
  fp_file = f"{get_base_dir()}/config/false_positive/{bug_variant}.json"
  if not os.path.exists(fp_file):
    return False
  with open(fp_file) as f:
    fp_data = json.load(f)
  if func_name in fp_data:
    if path in fp_data[func_name]:
      if fp_data[func_name][path] == num:
        return True 
  return False

def parse_final_report(json_path, func_name, bug_variant):
  all_report_str = ''
  with open(json_path) as f:
    data = json.load(f)
  for path in data:
    if match_false_positive(bug_variant, 
        func_name, noprefix_path(path), len(data[path])):
      logger.debug (f"Skip FP {func_name}, {path}")
      continue
    for lines in data[path]:
      all_report_str += (f"\t {noprefix_path(path)}:{lines} : {data[path][lines]}\n")
  return all_report_str
  

def parse_all_reports(bug_variant, temp_dir, violation_func_list):
  """
    For bug variant that has both violation function and abuse function
  """
  total_report_count = 0
  for func_path in violation_func_list:
    for vfunc in violation_func_list[func_path]:
      final_report_path = f"{temp_dir}/result/{bug_variant}/{clean_func_name(vfunc)}-abuse.json"
      if not os.path.exists(final_report_path):
        logger.debug (f"{clean_func_name(vfunc)}, {final_report_path} not found")
        continue
      func_line = violation_func_list[func_path][vfunc]
      all_report_str = parse_final_report(final_report_path, clean_func_name(vfunc), bug_variant)
      if all_report_str != '':
        logger.info (f"Violation function is found at {noprefix_path(func_path)}:{func_line[0]}, {better_func_name(vfunc)}")
        print (all_report_str)
      total_report_count += all_report_str.count('\n')
  return total_report_count


def parse_raw_reports(bug_variant, temp_dir):
  """
    For bug variant that only automate the violation/abuse
  """
  all_report_str = ''
  raw_report_path = f"{temp_dir}/result/{bug_variant}/all-abuse.json"
  with open(raw_report_path) as f:
    data = json.load(f)
  for path in data:
    for vfunc in data[path]:
      lines = data[path][vfunc][0]
      all_report_str += f"\t{noprefix_path(path)}:{lines} : {clean_func_name(vfunc)}\n"
  print (all_report_str)
  return all_report_str.count('\n')


if __name__ == "__main__":
#   # parse_violation_report('temp/violation/ui-20241119_153308.json', '', 'ui')
  with open('debug.json') as f:
    violation_func_list = json.load(f)
  print (len(violation_func_list.keys()))
  parse_all_reports('ui', 'temp/', violation_func_list)