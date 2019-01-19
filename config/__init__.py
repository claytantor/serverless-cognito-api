import yaml
import sys, os

def get_config():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open("{0}/config.yaml".format(dir_path), 'r') as ymlfile:
        cfg = yaml.load(ymlfile)

    return cfg
