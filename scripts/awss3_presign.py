#!/usr/bin/python
# Amazon S3 presigned URL generator for Zendesk tickets.
# www.sysdig.com
#
# (c) 2017 Sysdig Inc.
#


import boto3
import sys


BUCKET_NAME = "log-bundle"
ZENDESK_DIR = "zendesk"
EXPIRE_PERIOD = 86400

if len(sys.argv) != 3:
    print "Usage: awss3_presign.py <filename.tar.bz2> <ticket id>"
    sys.exit(1)
FILENAME = sys.argv[1]
TICKET_ID = sys.argv[2]

FILEPATH = "%s/%s/%s" % (ZENDESK_DIR, TICKET_ID, FILENAME)

s3 = boto3.client("s3")
url = s3.generate_presigned_url("put_object", Params = {"Bucket": BUCKET_NAME, "Key": FILEPATH}, ExpiresIn = EXPIRE_PERIOD)
print url
