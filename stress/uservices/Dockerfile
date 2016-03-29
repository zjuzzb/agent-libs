FROM ubuntu:14.04

# Install Python Setuptools
RUN apt-get install -y python-setuptools

# Install pip
RUN easy_install pip

# Add and install Python modules
ADD . /src
RUN cd /src

# Expose
EXPOSE  5000

# Run
CMD ["python", "/src/us.py"]