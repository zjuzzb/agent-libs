#!/usr/bin/env python3
#
# fault_injection.py
#
# Simple Python script to interface with the Sysdig Agent's Fault Injection
# Framework REST API endpoint.
#
# To get a list of faults:
#
#     $ fault_injection.py
#
# To view a single fault by name:
#
#     $ fault_injection.py --fault <fault_name>
#
# To modify a fault by name (here, for example, we enable it, change the fault
# mode to PROBABILITY, and change the fault probability to 50%:
#
#     $ fault_injection.py --modify --fault <fault_name> --enable true --mode PROBABILITY --probability 50
#

import argparse
import json
import requests

def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'yep', 'ohyeah', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'nope', 'noway', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

def main():
    parser = argparse.ArgumentParser(description="Sysdig Agent Fault Injection Tool")
    parser.add_argument("--verbose",
                        "-v",
                        action="store_true",
                        help="Enable verbose logging")
    parser.add_argument("--address",
                        help="The IP address of the Agent host (default: 127.0.0.1)",
                        default="127.0.0.1")
    parser.add_argument("--port",
                        type=int,
                        help="The TCP port on which the Agent REST API is listening (default: 24482)",
                        default=24482)
    parser.add_argument("-f",
                        "--fault",
                        help="The name of the fault to get/set")
    parser.add_argument("-e",
                        "--enabled",
                        type=str2bool,
                        help="Enable/disabled the named fault")
    parser.add_argument("-s",
                        "--string",
                        help="Update the fault string for the named fault")
    parser.add_argument("-u",
                        "--uint64",
                        help="Update the fault uint64 for the named fault")
    parser.add_argument("-n",
                        "--n_count",
                        help="Update the fault n_count for the named fault")
    parser.add_argument("-m",
                        "--mode",
                        help="Update the fault mode for the named fault")
    parser.add_argument("-p",
                        "--probability",
                        help="Update the fault probability for the named fault")
    parser.add_argument("--modify",
                        action="store_true",
                        help="Modify the named fault")

    args = parser.parse_args()


    if args.fault is None:
        app_url = "http://{}:{}/api/fault_injections".format(args.address, args.port)

        if args.verbose is not None and args.verbose:
            print("URI: {}".format(app_url))

        response = requests.get(app_url)
    else:
        app_url = "http://{}:{}/api/fault_injection/{}".format(args.address, args.port, args.fault)

        if args.verbose is not None and args.verbose:
            print("URI: {}".format(app_url))

        if not args.modify:
            response = requests.get(app_url)
        else:
            data = {}

            if args.enabled is not None:
                data['enabled'] = bool(args.enabled)

            if args.string is not None:
                data['fault_string'] = str(args.string)

            if args.uint64 is not None:
                data['fault_uint64'] = int(args.uint64)

            if args.n_count is not None:
                data['n_count'] = int(args.n_count)

            if args.mode is not None:
                data['mode'] = str(args.mode)

            if args.probability is not None:
                data['probability'] = int(args.probability)

            if args.verbose is not None and args.verbose:
                print(json.dumps(data, indent=4, sort_keys=True))

            response = requests.put(app_url, json.dumps(data))

    if response.status_code == 200:
        body_json = json.loads(response.content.decode('utf-8'))
        print(json.dumps(body_json, indent=4, sort_keys=True))

if __name__ == "__main__":
    main()
