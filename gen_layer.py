# Please note that this script was based on the original code developed by MITRE ATT&CK team used for the generation of
# ATT&CK Navigator files.  This script was slightly modified and configured to output JSON file instead.
# https://github.com/mitre/attack-navigator

# attack_layers_simple.py - the "hello, world" for ATT&CK Navigator layer generation
# Takes a simple CSV file containing ATT&CK technique IDs and counts of groups, software and articles/reports that reference this technique
# and generates an ATT&CK Navigator layer file with techniques scored and color-coded based on an algorithm
# This sample is intended to demonstrate generating layers from external data sources such as CSV files.

import argparse
import csv
import json
import sys
import os

# Static ATT&CK Navigator layer JSON fields
VERSION = "2.0"
NAME = "ATT&CK with Empire"
DESCRIPTION = "ATT&CK Matrix Techniques used from PowerShell Empire"
DOMAIN = "Galactic Empire"

# Changed to function
def generate():

    # handle arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", action="store", dest="input_fn", default="attack.csv",
                        required=False, help="input ATT&CK csv file with tactic ID, groups, software, etc... fields")

    args, extras = parser.parse_known_args()

    # Base ATT&CK Navigator layer
    layer_json = {
        "version": VERSION,
        "name": NAME,
        "description": DESCRIPTION,
        "domain": DOMAIN,
        "techniques": []
    }

    # parse csv file, calculating a score for each technique and adding that to the layer
    with open(args.input_fn, "rb") as csvfile:
        reader = csv.DictReader(csvfile, delimiter=",")
        for row in reader:
            # score each technique based on a simple formula
            technique = {
                "techniqueID": row["TechID"],
                "score": (int(row["Software"]) + int(row["Groups"]))*2 + int(row["References"])
            }

            layer_json["techniques"].append(technique)


    # add a color gradient (white -> red) to layer
    # ranging from zero (white) to the maximum score in the file (red)
    layer_json["gradient"] = {
        "colors": [
            "#ffffff",
            "#ff6666"
        ],
        "minValue": 0,
        "maxValue": max([technique["score"] for technique in layer_json["techniques"]])
    }

    # commenting in order to output file instead
    #json.dump(layer_json, sys.stdout, indent=4)

    #Output JSON file instead of stdout
    with open('att&ck_layer.json', 'w') as outfile:
        json.dump(layer_json, outfile, indent=4)
    cwd = os.getcwd()
    print "\nOutput of layer successful: " + cwd + "\\att&ck_layer.json"
    print "\nLayer view options:"  + "\n\t 1. MITRE-hosted ATT&CK Navigator: https://mitre.github.io/attack-navigator/enterprise/ " + \
          "\n\t 2. Deploy own instance of ATT&CK Navigator: https://github.com/mitre/attack-navigator"


if __name__ == '__main__':
    #layer.py executed as script
    generate()