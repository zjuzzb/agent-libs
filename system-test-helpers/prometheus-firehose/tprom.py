#!/usr/bin/env python

from prometheus_client import start_http_server, Gauge
import time
import math

def sine(x,period,amp,c):
    return c + (amp * math.sin(x * 2 * math.pi / period))

if __name__ == '__main__':
    # Start up the server to expose the metrics.
    start_http_server(5005)
    g = Gauge('thom_sine', 'Wave', ['period'])
    x = 0
    while True:
        g.labels(period='30+300').set(sine(x, 30, 10, 10) + sine(x, 300, 10, 10))
        g.labels(period='60+600').set(sine(x, 60, 10, 10) + sine(x, 600, 10, 10))
        x += 1
        time.sleep(1)
