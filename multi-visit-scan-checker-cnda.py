#!/usr/bin/python
import copy
import nipy
import nipype
from nipype.algorithms.metrics import Similarity
import argparse
import os
from macpath import dirname
import argparse
import fnmatch
import os
import shutil
import sys
import tempfile
from datetime import datetime
import ntpath
import numpy as np
import json
import zipfile

import dicom
from nibabel.tests.test_api_validators import ValidateAPI
from numpy.lib.arraysetops import in1d
from pyxnat import Interface
import requests
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()
# If SPM is not in your MATLAB path you should add it here

class ScanDetails(object):
    def __init__(self, project, subject, session,scan,scan_location,value):
        self.project=project
        self.subject=subject
        self.session=session
        self.scan=scan
        self.scan_location=scan_location
        self.value=value
    def __str__(self):
        return  self.project,self.subject,self.session,self.scan,self.scan_location,self.value

def getPrevious(list):
    previous=[]
    for detail in list:
        previous.append(detail)
    return previous

def findSessions(server,project,subject,match,output,xsitype,compareAll):
    
    sub=server.select.project(project).subject(subject)
    current_scan_locations=[]
    previous_scan_locations=[]
    current_scans=[]
    previous_scans=[]
    scan_details=[]
    all_experiments=sorted([exp for exp in sub.experiments() if exp.attrs.get('xsiType') == xsitype],key=lambda x:x.attrs.get('date'),reverse=True)
    if compareAll == "False":
        experiments = all_experiments[0:2]
    else:
        experiments = all_experiments
    for exp in experiments:
        the_scans=findScans(server,project,sub,exp,match)
        scan_details.extend(download(the_scans,project,subject,exp,match,output))

    return scan_details;
                
def download(scans,project,subject,exp,match,output):
    scan_locations=[]
    for ascan in scans:
        os.system("mkdir "+ output+"/"+exp.attrs.get('label'))
        os.system("mkdir "+ output+"/"+exp.attrs.get('label')+"/"+ascan.attrs.get('ID'))
        scan_location=output+"/"+exp.attrs.get('label')+"/"+ascan.attrs.get('ID')
        ascan.resource('DICOM').get(scan_location, extract=True)
        #scan_locations.append(scan_location)
        scan_locations.append(ScanDetails(project,subject,exp.attrs.get('label'),ascan.attrs.get('ID'),scan_location,0))
    return  scan_locations   
        
def findScans(server,project,sub,exp,match):
    scans = exp.scans().get()
    
    selected_scans=[]

    for scan in scans:
                ascan = exp.scan(scan)
                ascanid=ascan.attrs.get('ID')
                ascantype=ascan.attrs.get('xsiType')
                try:
                    type = ascan.attrs.get('type')
                    if debug == 'True':
                         print ("type: "),type
                except IndexError:
                    found=False
                #print ascan.attrs.get('series_description')

                thetime=str(datetime.now()); 
                if debug == 'True':
                    print ("\tChecking:"),sub.attrs.get('project'),sub.attrs.get('label'),exp.attrs.get('label'),exp.attrs.get('insert_date'),("ID:"),ascanid, ("type: "),type  ,ascan.attrs.get('quality')
                if type.lower() in match.lower():
                    selected_scans.append(ascan)
                    print ("\tANALYSIS:"),sub.attrs.get('project'),sub.attrs.get('label'),exp.attrs.get('label'),exp.attrs.get('insert_date'),("ID:"),ascanid, ("type: "),type  ,ascan.attrs.get('quality')
                    break
                        
    return selected_scans;              
    
    
def shellquote(s):
    stuff= s.replace(" ", "\ ")
    return stuff
        
def dcm2nii(outputdir,dicomdir): 
    command="dcm2nii -g N -n Y  -o "+outputdir+" "+ dicomdir
    print (command)
    os.system(command)
    
def gunzip(dicomdir): 
    command="gunzip -f "+dicomdir
    print (command)
    os.system(command)
    
def similarity_old(source,destination): 
     command="similarity.py  --source "+source+" --destination "+ destination
     print (command)
     #os.system(command)   
     theoutput = commands.getstatusoutput(command)
     print (theoutput)
     return theoutput
     
def getFile(dirname,thetype):
    for afile in os.listdir(dirname):
        if afile.endswith(thetype):
            return os.path.join(dirname, afile)  
    return ""
    
#def affine(dirname,source,destination,outputfile): 
#     command="export FSL_OUTPUTTYPE=NIFTI_PAIR;flirt -in "+source+" -ref "+ destination+" -out "+ outputfile
 #    print command
 #    os.system(command)   
     
#sh   antsaffine.sh  ImageDimension  fixed.ext  moving.ext 
def affine(dirname,source,destination,outputfile): 
     command="antsaffine.sh  3 "+destination+" "+ source+" "
     print (command)
     os.system(command)   
     
         
def compareSingle(current_scan,previous_scan):
    print ("similarity"),current_scan.scan_location,previous_scan.scan_location
   # gunzip(current_scan.scan_location+"/*.nii")
    #gunzip(previous_scan.scan_location+"/*.nii")
    os.system("rm "+current_scan.scan_location +"/co*.nii")
    os.system("rm "+current_scan.scan_location +"/o*.nii")
    
    nii_current=getFile(current_scan.scan_location,".nii")
    nii_previous=getFile(previous_scan.scan_location,".nii")
    
    nii_current2previous_gz=nii_current+"linear.nii"
    affine(current_scan.scan_location,nii_current,nii_previous,nii_current2previous_gz)
    gunzip(current_scan.scan_location+"/*deformed.nii.gz")
    nii_current2previous=getFile(current_scan.scan_location,"deformed.nii")
    value=similarity(nii_current2previous,nii_previous)
    
    return (current_scan.session,current_scan.scan,previous_scan.session,previous_scan.scan,str(value[0]))
    
    
def timeStamped(fname, fmt='%Y-%m-%d-%H-%M-%S_{fname}'):
    return datetime.datetime.now().strftime(fmt).format(fname=fname)
    
def compareAllPrevious(previous_scans,compareAll):
    report=[]
    n = len(previous_scans)-1
    if compareAll=="False":
        current_scan=previous_scans[n-1]
        previous_scan=previous_scans[n]
        report.append(compareSingle(current_scan,previous_scan))

    else:
        for scan in previous_scans:
            if n == 0:
                break
            current_scan=previous_scans[n]
            previous_scan=previous_scans[n-1]
            report.append(compareSingle(current_scan,previous_scan))
            n = n-1

    return report


def compareScans(all_scan_details):
    #dcm2nii
    for all in all_scan_details:
        dcm2nii(all.scan_location,all.scan_location)
    
    
    previous_scans = getPrevious(all_scan_details);
    
    return compareAllPrevious(previous_scans,compareAll)

def similarity(source,destination):

    owd = os.getcwd()
    os.chdir(os.path.dirname(os.path.abspath(source)))
    os.chdir(os.path.dirname(os.path.abspath(destination)))


    #Similarity algorithm from Nipype: run1 
    similarity=Similarity()

    similarity.inputs.volume1 = source
    similarity.inputs.volume2 = destination
    similarity.inputs.metric = 'cc'
    res = similarity.run()
    print (res.outputs.similarity)
    return res.outputs.similarity;

desc= 'Multi Visit Checker Script v1.0 (James Dickson Thursday 27 April 2017)'
print (desc)

parser = argparse.ArgumentParser(description=desc)
group = parser.add_argument_group('Required')
group.add_argument('--compareAll', action="store", default="False", dest='compareAll', required=False, help='compare all')
group.add_argument('--subject', action="store", dest='subject', required=True, help='subject')
group.add_argument('--project', action="store", dest='project', required=True, help='project')
group.add_argument('--match', action="store", dest='match', required=True, help='match scans')
group.add_argument('--host', action="store", default= '', dest='host', required=True, help='host')
group.add_argument('--username', action="store", default= '', dest='username', required=False, help='username')
group.add_argument('--password', action="store", default= '', dest='password', required=False, help='password')
group.add_argument('--debug', action="store", default= "False", dest='debug', required=False, help='debug')
group.add_argument('--process', action="store", default= "False", dest='process', required=False, help='process')
group.add_argument('--output', action="store", dest='output', required=True, help='output')
group.add_argument('--xsitype', action="store", dest='xsitype', required=True, help='xsitype')


inputArguments = parser.parse_args()

username = inputArguments.username
passwd = inputArguments.password
host=inputArguments.host

project=inputArguments.project

subject=inputArguments.subject

compareAll=inputArguments.compareAll
match=inputArguments.match
output=inputArguments.output
xsitype=inputArguments.xsitype


server=Interface(server=host, user=username, password=passwd,cachedir='/tmp',verify=False)
debug = inputArguments.debug

s = requests.Session()
s.auth = (username,passwd)
s.verify=False
fileName='similarityreport.csv'
if compareAll == "False":
    r=s.get(host+'/data/projects/'+project+'/subjects/'+subject+'/resources/Similarities/files/'+fileName)
    if r.ok:
        with open(output+'/'+fileName,'w') as file:
            file.write(r.text)

try:
    all_scan_details= findSessions(server,project,subject,match,output,xsitype,compareAll)
except zipfile.BadZipfile:
        print "This subject has bad Zip files."

if len(all_scan_details)<2:
    print "This subject does not have 2 or more sessions with matching scans."
    sys.exit("This subject does not have 2 or more sessions with matching scans.")

report=compareScans(all_scan_details)
        
#        uploadReportSummary(server,Project,Label,Sessionlabel,report,xsitype)

# print (report)


folder = output
for the_file in os.listdir(folder):
    file_path = os.path.join(folder, the_file)
    try:
        if os.path.isdir(file_path):
            shutil.rmtree(file_path)
    except Exception as e:
        print(e)

with open(output+'/'+fileName,'a+') as file:
    for reportline in report:
        file.write(','.join(reportline)+'\n')

r = s.delete(host+'/data/projects/'+project+'/subjects/'+subject+'/resources/Similarities')
if not r.ok and r.status_code != 404:
    sys.exit(r.text)
r = s.put(host+'/data/projects/'+project+'/subjects/'+subject+'/resources/Similarities')
if not r.ok:
    sys.exit(r.text)
r = s.put(host+'/data/projects/'+project+'/subjects/'+subject+'/resources/Similarities/files', files={'file':open(output+'/'+fileName,'rb')})
if not r.ok:
    sys.exit(r.text)

# result[Label] = report[0][0]

#        resultcsv = '\n'.join([k+','+str(v) for k,v in result.iteritems()])
