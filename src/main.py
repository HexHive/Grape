from utils import *
from violation import get_violation_list, get_violation_only
from abuse import get_all_abuse, count_vuln_num, get_all_abuse_single, get_abuse_only
from paser import *

import argparse

logger = get_logger(__name__)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Process repository path and bug variant.")
    parser.add_argument('-r', '--repo_path', required=True, help="Path to the repository")   
    parser.add_argument('-t', '--temp_path', required=True, help="Path to the temp dir") 
    parser.add_argument('bug_variant', choices=available_bug_variants.keys(), 
                        help="Bug variant to process (e.g., 'ui', 'js')")    
    args = parser.parse_args()
    
    return args

def main():
  args = parse_arguments()
  prepare_semgrep_ignore()

  repo_path = args.repo_path
  bug_variant = args.bug_variant
  temp_dir = args.temp_path
  bug_variant_config = get_bug_variant_config()
  auto_violation = bug_variant_config[bug_variant]['violation']
  auto_abuse = bug_variant_config[bug_variant]['abuse']
  if bug_variant == 'js':
    repo_path = f"{repo_path}/third_party/pdfium"
  elif bug_variant == 'uar':
    repo_path = f"{repo_path}/third_party/blink"
  elif bug_variant == 'int_overflow':
    # if we don't specify, the libyuv is a sub-repo and will not be scanned
    repo_path = f"{repo_path}/third_party/libyuv"
  elif bug_variant == "int_overflow_constructor":
    repo_path = f"{repo_path}/third_party/webrtc"
  elif bug_variant == "int_overflow_add":
    repo_path = f"{repo_path}/third_party/skia"


  # working on the violation
  if auto_violation and auto_abuse:
    # violation processing
    violation_func_list = get_violation_list(bug_variant, repo_path, temp_dir)
    violation_num = count_vuln_num(violation_func_list)
    logger.info (f"In total, we found {violation_num} violation functions.")
    # abuse processing
    total_vuln_num = get_all_abuse(bug_variant, repo_path, temp_dir, violation_func_list)
    logger.info (f"In total, we found {total_vuln_num} potential vulnerbilities among {violation_num} violation functions.")
    total_tp_num = parse_all_reports(bug_variant, temp_dir, violation_func_list)
    logger.info (f"{total_tp_num} among them are potential vulnerbilities after excluding the FPs.")
  elif auto_abuse:
    # for abuse/violation only, it's same as running semgrep directly
    # ToDo: automate the violation extraction when semgrep support C++ class defination
    total_vuln_num = get_abuse_only(bug_variant, repo_path, temp_dir)
    logger.info (f"In total, we found {total_vuln_num} potential vulnerbilities")
    total_tp_num = parse_raw_reports(bug_variant, temp_dir)
    logger.info (f"{total_tp_num} among them are potential vulnerbilities after excluding the FPs.")
  elif auto_violation:
    total_vuln_num = get_violation_only(bug_variant, repo_path, temp_dir)
    logger.info (f"In total, we found {total_vuln_num} potential vulnerbilities")
    total_tp_num = parse_raw_reports(bug_variant, temp_dir)
    logger.info (f"{total_tp_num} among them are potential vulnerbilities after excluding the FPs.")
    

if __name__ == "__main__":
    main()

