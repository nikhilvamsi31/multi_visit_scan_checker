FROM python:2.7.11

RUN pip install nipy numpy nipype prov dicom nose pyxnat

ADD multi-visit-scan-checker-cnda.py /

COPY multi-visit-scan-checker/scripts/mricron /usr/local/mricron
COPY multi-visit-scan-checker/scripts/scripts /usr/local/scripts
COPY multi-visit-scan-checker/scripts/ANTS /usr/local/ANTS
ENV PATH=$PATH:/usr/local/ANTS/bin/:/usr/local/mricron/:/usr/local/scripts/ ANTSPATH=/usr/local/ANTS/bin/