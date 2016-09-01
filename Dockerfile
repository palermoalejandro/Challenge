FROM partlab/ubuntu

MAINTAINER Alejandro Palermo "palermo.alejandro@gmail.com"



##################################################################

#       Dockerfile to build MeLi Challenge

##################################################################







# Set locales

RUN locale-gen en_GB.UTF-8

ENV LANG en_GB.UTF-8

ENV LC_CTYPE en_GB.UTF-8

ENV INITRD No







RUN apt-get update && \

    apt-get install -y \
		build-essential \

        curl \

        wget \

        git \

        vim \

		dialog \

		software-properties-common \

        zip \

		net-tools \

        python3.5 \

        python-dev \

        python-distribute \

        python3-setuptools\

        python3-pip


#Workaround to use source command that is part of the bash built-in services required for next steps



RUN rm /bin/sh && ln -s /bin/bash /bin/sh





#PIP


RUN pip3 install beautifulsoup4

RUN pip3 install docopt

RUN pip3 install tabulate

RUN pip3 install requests

RUN pip3 install tld


RUN mkdir /app


#Add challenge App

ADD challenge.py /app

ADD tests.py /app
