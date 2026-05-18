import logging
import os


__is_fast_scan = False

__SYS_NAME = 'BGREP'

def is_fast_scan():
  return __is_fast_scan

__logging_level = logging.INFO
def logging_level():
  return __logging_level


def get_base_dir():
  return os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

available_bug_variants = {
  
  'ui' : {'type' : 'Use-After-Free', 'violation' : True, 'abuse' : True},
  'js' : {'type' : 'Use-After-Free', 'violation' : True, 'abuse' : True},
  'uar' : {'type' : 'Use-After-Return', 'violation' : False, 'abuse' : True},
  'int_overflow' : {'type' : 'Integer Overflow', 'violation' : True, 'abuse' : False},
  'int_overflow_constructor' : {'type' : 'Integer Overflow', 'violation' : True, 'abuse' : False},
  'int_overflow_add' : {'type' : 'Integer Overflow (Add)', 'violation' : True, 'abuse' : False},
  'logical' : {'type' : 'Improper Access Control', 'violation': True, 'abuse' : False},
  'logical_cmd' : {'type' : 'Improper Access Control (CLI argv leak)', 'violation': True, 'abuse' : False}
}

def get_bug_variant_config():
  return available_bug_variants

safe_abuse_list = {
  'ui' : ['safe_no_weakptr_template.yaml', 'safe_weakptr_template.yaml'],
  'js' : ['safe_no_weakptr_template.yaml', 'safe_weakptr_template.yaml'],
}

def get_safe_abuse_list(bug_variant):
  return safe_abuse_list[bug_variant]

keywords = {
  'ui' : '$FREE_FUNC',
  'js' : '$FREE_FUNC',
  'uar' : '$RET_VALUE',
  'int_overflow' : '$BUFFER',
  'int_overflow_constructor' : '$MULT_OPERATION',
  'int_overflow_add' : '$KEY_VAR',
  'logical' : '$DIR_NAME',
  'logical_cmd' : '$DIR_NAME'
}

def get_keywords(bug_variant):
  return keywords[bug_variant]
