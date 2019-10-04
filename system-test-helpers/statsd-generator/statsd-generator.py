#!/usr/bin/env python

import os
import random
import string
import time

from socket import *


def gen_metrics_names(num_metrics):
    return [''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            for _ in range(num_metrics)]

    
def get_stats_prefix():
    """
    Return the hostname if the HOSTNAME env variable is set, otherwise
    return a random selection from a list of Norse gods.
    :return: Pod|Host name
    """
    fake_hostnames = ["odin", "frigg", "balder", "loki", "freya", "freyr", "heimdall",
                      "hel", "vidar", "vale"]
    return os.environ.get("HOSTNAME", random.choice(fake_hostnames))


def firehose(ip, port, num_metrics, delay, metrics_per_request):
    """

    :param ip:
    :param port:
    :param delay:
    :param num_metrics:
    :param metrics_per_request:
    :return:
    """
    generated_metrics = gen_metrics_names(num_metrics)
    metric_sets = [generated_metrics[i:i+50] for i in range(0, len(generated_metrics), 50)]

    count = 0
    increasing = True
    
    my_sock = socket(AF_INET, SOCK_DGRAM)
    while True:
        if count == 50:
            increasing = False
        elif count == 0:
            increasing = True
        for metric_set in metric_sets:
            msg = '\n'.join(['{}.{}:{}|g'.format(get_stats_prefix(), metric, count) for metric in metric_set])
            my_sock.sendto(msg.encode(), ("localhost", 8125))
        count = count + 1 if increasing else count - 1
        time.sleep(delay)


if __name__ == "__main__":
    ip = os.environ.get("IP", "localhost")
    port = int(os.environ.get("PORT", 8125))
    delay = float(os.environ.get("DELAY", 2))
    num_metrics = int(os.environ.get("NUM_METRICS", 100))
    metrics_per_request = int(os.environ.get("METRICS_PER_REQUEST", 10))

    firehose(ip, port, num_metrics, delay, metrics_per_request)
