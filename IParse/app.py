import ntpath
import os
import datetime
import re
import socket
import subprocess
import sys
import shodan
from collections import defaultdict

import dpkt
import pyshark
import ipaddress
from flask import (Flask, Response, flash, json, redirect, render_template,
                   request, session, url_for, make_response)
from json2html import json2html
from pcapng import FileScanner
from werkzeug.utils import secure_filename
from wtforms import (Form, StringField, SubmitField, TextAreaField, TextField,
                     validators)

# Flaskapp config.
FLASK_DEBUG = True
flaskapp = Flask(__name__)
flaskapp.config.from_object(__name__)

###################################Configure This###################################
SHODAN_API_KEY = ""
api = shodan.Shodan(SHODAN_API_KEY)

###################################Configure This###################################
flaskapp.secret_key = "CH4NG3M3"

###################################Configure This###################################
UPLOAD_FOLDER = '/root/Documents/project/venv/IParse/uploads/'

ALLOWED_EXTENSIONS = set(['pcap'])
SESSION_TYPE = 'filesystem'
cmd="mkdir -p %s && ls -lrt %s"%(UPLOAD_FOLDER,UPLOAD_FOLDER)
flaskapp.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# # Set file structure for css usage
# BASE_DIR = ''
# STATIC_ROOT = os.path.join(os.path.dirname(BASE_DIR), "static_in_env", "static_root")

#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#! SET DEBUG MODE TO FALSE AND CHANGE UPLOAD_FOLDER WHEN GOING INTO PRODUCTION
#! SET THREADED TO FALSE IN FLASK CONSTRUCTOR (IN BOTTOM OF app.py FILE)
#! UPLOADED_FILES_URL = If you have a server set up to serve the files in this set this should be the URL they are publicly accessible from. Include the trailing slash.
#! UPLOADS_DEFAULT_DEST = If you set this, then if an upload sets destination isn't otherwise declared, then its uploads will be stored in a subdirectory of this directory. For example, if you set this to /var/uploads, then a set named photos will store its uploads in /var/uploads/photos.
#! UPLOADS_DEFAULT_URL = If you have a server set up to serve from UPLOADS_DEFAULT_DEST, then set the server's base URL here. Continuing the example above, if /var/uploads is accessible from http://localhost:5001, then you would set this to http://localhost:5001/ and URLs for the photos set would start with http://localhost:5001/photos. Include the trailing slash.
#! patch_request_class(flaskapp, 32 . 1024 . 1024) make max upload size 32 megabytes
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

# Redirect away from root directory towards step 1: uploading a .pcap file
@flaskapp.route('/', methods=['GET', 'POST'])
def redirectFromRoot():
    return redirect(url_for('uploadPage'))

# 1: Uploading a .pcap file page
@flaskapp.route('/upload', methods=['GET', 'POST'])
def uploadPage():
    output = subprocess.Popen([cmd], shell=True,  stdout = subprocess.PIPE).communicate()[0]

    if "total 0" in output:
        print "Success: Created Directory %s"%(UPLOAD_FOLDER) 
    else:
        print "Failure: Failed to Create a Directory (or) Directory already Exists",UPLOAD_FOLDER
    flashthismessage = 'Upload .pcap file:'
    flashthismessagetoo = 'Select the file'
    form = ReusableForm(request.form)
    print form.errors
    # Check if the post request has the file part
    if request.method == 'POST':
        if 'file' not in request.files:
            flashthismessage = 'No file part'
            return render_template('upload.html', form=form, flashthismessage=flashthismessage)

        # Store uploaded file in a variable
        file = request.files['file']

        # If no file is selected
        if file.filename == '':
            flashthismessage = 'No selected file'
            return render_template('upload.html', form=form, flashthismessage=flashthismessage)

        # If file is not a .pcap file
        if file.filename != allowed_file(file.filename):
            flashthismessage = 'Only .pcap files can be uploaded'

        # If file is of type .pcap then store the .pcap file, save filename in session var and redirect
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(flaskapp.config['UPLOAD_FOLDER'], filename))
            session['filename'] = filename
            return redirect(url_for('enterInfo'))

    return render_template('upload.html', form=form, flashthismessage=flashthismessage, flashthismessagetoo=flashthismessagetoo)

# 2:
@flaskapp.route('/info', methods=['GET', 'POST'])
def enterInfo():
    # Get filename here to pass to flashthismessage
    filename = session.get('filename', None)
    flashthismessage = 'Capture file has been uploaded with filename: %s ' % filename
    form = ReusableForm(request.form)

    if request.method == 'POST':

        if form.validate():
            session['message'] = 'parsing...'

            # This redirect does not work, but does activate parse()
            return redirect(url_for('waitingPage'))

            # This redirect works, but does not activate parse()
            # return render_template('wait.html', message=session.get('message', None))
        else:
            # If something went wrong
            flashthismessage = 'Something went wrong. '

    return render_template('enterInfo.html', form=form, flashthismessage=flashthismessage)

# 3: Waiting page for parsing process to complete
@flaskapp.route('/wait', methods=['GET', 'POST'])
def waitingPage():
    if request.method == 'POST':
        return redirect(url_for('waitingPage'))

    filename = session.get('filename', None)
    message = session.get('message', None)
    print 'waiting'
    flashthismessage = 'Waiting for process to complete'
    while parse(filename):
        # When done redirect to summary page
        return redirect(url_for('summaryPage'))
    else:
        flashthismessage = 'Something went wrong with parsing, could not complete'
        return render_template('upload.html', flashthismessage=flashthismessage)

    return render_template('wait.html', flashthismessage=flashthismessage, message=message)

# 4: Summary
@flaskapp.route('/summary', methods=['GET', 'POST'])
def summaryPage():
    if request.method == 'POST':
        return redirect(url_for('uploadPage'))

    form = ReusableForm(request.form)
    json_data = open(os.path.join(
        UPLOAD_FOLDER) + 'shodan-json.json', 'r').read()
    flashthismessage = "File has been parsed"

    if request.method == 'POST':
        return redirect(url_for('shodanAnalyze'))

    return render_template('shodan.html', form=form, flashthismessage=flashthismessage, message=json_data)

# 5: Page for analyzing the IP's that did not resolve into a hostname which means it probably serves a different role
@flaskapp.route('/shodan', methods=['GET', 'POST'])
def shodanAnalyze():
    # If home button is pressed then return to homepage
    if request.method == 'POST' and request.values == 'To Shodan':
        return redirect(url_for('shodan'))

    if request.method == 'POST' and request.values == 'To Upload':
        return redirect(url_for('uploadPage'))

    print 'Going into shodanAnalyze'
    # flashthismessage = "Analyze IP's that did not resolve"
    form = ReusableForm(request.form)
    print form.errors
    # generalSRCInfo = []
    detailedSRCInfo = []
    # generalDSTInfo = []
    detailedDSTInfo = []
    analyzeThis = session['parse']

    print 'analyzeThis == %s ' % analyzeThis
    for key in analyzeThis:
        print 'looping through key %s' % key
        if isinstance(analyzeThis[key][3], (int, long, float)) == True:
            try:
                if ipaddress.ip_address(analyzeThis[key][3]).is_private == True:
                    print 'Private IP-address. Not looking up'
                    return
                else:
                    try:
                        # Lookup the host
                        host = api.host(analyzeThis[key][1])

                        # Store general info
                        # generalSRCInfo.append("""
                        #         IP: {}
                        #         Organization: {}
                        #         Operating System: {}
                        #         """.format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))

                        # Store all banners
                        for item in host['data']:
                            detailedSRCInfo.append("""
                                    Port: {}
                            """.format(item['port']))
                        # print 'general source %s' % generalSRCInfo
                        # print 'detailed source %s' % detailedSRCInfo
                        # analyzeThis[key][5] = generalSRCInfo
                        analyzeThis[key][5].append(
                            "Open ports on ")
                        analyzeThis[key][5].append(analyzeThis[key][3])
                        analyzeThis[key][5].append(detailedSRCInfo)
                    except:
                        analyzeThis[key][5].append("No open ports on ")
                        analyzeThis[key][5].append(analyzeThis[key][3])
                        print '%s can not be looked up' % analyzeThis[key][1]
            except:
                print 'Not an IP-address. Looking up anyway'
                continue
        else:
            try:
                # Lookup the host
                host = api.host(analyzeThis[key][1])

                # Store general info
                # generalSRCInfo.append("""
                #         IP: {}
                #         Organization: {}
                #         Operating System: {}
                #         """.format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))

                # Store all banners
                for item in host['data']:
                    detailedSRCInfo.append("""
                            Port: {}
                    """.format(item['port']))
                # print 'general source %s' % generalSRCInfo
                # print 'detailed source %s' % detailedSRCInfo
                # analyzeThis[key][5] = generalSRCInfo
                analyzeThis[key][5].append(
                    "Open ports on ")
                analyzeThis[key][5].append(analyzeThis[key][3])
                analyzeThis[key][5].append(detailedSRCInfo)
            except:
                analyzeThis[key][5].append("No open ports on ")
                analyzeThis[key][5].append(analyzeThis[key][3])
                print '%s can not be looked up' % analyzeThis[key][1]

        if isinstance(analyzeThis[key][4], (int, long, float)) == True:
            try:
                if ipaddress.ip_address(analyzeThis[key][4]).is_private == True:
                    print 'Private IP-address. Not looking up'
                    return
                else:
                    try:
                        # Lookup the host
                        host = api.host(analyzeThis[key][1])

                        # Store general info
                        # generalSRCInfo.append("""
                        #         IP: {}
                        #         Organization: {}
                        #         Operating System: {}
                        #         """.format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))

                        # Store all banners
                        for item in host['data']:
                            detailedSRCInfo.append("""
                                    Port: {}
                            """.format(item['port']))
                        # print 'general source %s' % generalSRCInfo
                        # print 'detailed source %s' % detailedSRCInfo
                        # analyzeThis[key][5] = generalSRCInfo
                        analyzeThis[key][5].append(
                            "Open ports on ")
                        analyzeThis[key][5].append(analyzeThis[key][3])
                        analyzeThis[key][5].append(detailedSRCInfo)
                    except:
                        analyzeThis[key][5].append(
                            "Could not look up or no open ports on ")
                        analyzeThis[key][5].append(analyzeThis[key][3])
                        print '%s can not be looked up' % analyzeThis[key][1]
            except:
                print 'Not an IP-address. Looking up anyway'
                continue
        else:
            try:
                # Lookup the host
                host = api.host(analyzeThis[key][2])

                # Store general info
                # generalDSTInfo.append("""
                #         IP: {}
                #         Organization: {}
                #         Operating System: {}
                #         """.format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))

                # Store all banners
                for item in host['data']:
                    detailedDSTInfo.append("""
                            Port: {}
                    """.format(item['port']))
                # print 'general destination %s' % generalDSTInfo
                # print 'detailed destination %s' % detailedDSTInfo
                # analyzeThis[key][6] = generalDSTInfo
                analyzeThis[key][6].append(
                    "Open ports on ")
                analyzeThis[key][6].append(analyzeThis[key][4])
                analyzeThis[key][6].append(detailedDSTInfo)
            except:
                analyzeThis[key][6].append(
                    "Could not look up or no open ports on ")
                analyzeThis[key][6].append(analyzeThis[key][4])
                print '%s can not be looked up' % analyzeThis[key][2]

    with open(os.path.join(UPLOAD_FOLDER) + 'shodan-json.json', 'w') as file:
        json.dump(analyzeThis, file)
    json_resp = json2html.convert(json=analyzeThis)

    return render_template('shodan.html', form=form, flashthismessage='Result of Shodan lookup: ')


# Parse the uploaded file for IP's by using .pcap file as variable filetoparse
# tempIPlist is a temporary list used in this function in order to loop through data
# IPdict is declared and used as final dictionary to store in Json
def parse(filename):
    filetoparse = dpkt.pcap.Reader(
        open(UPLOAD_FOLDER + str(filename), "rb"))  # For use with dpkt module
    packetnr = 0
    counter = 0
    shodansrc = []
    shodandst = []
    tempIPlist = []
    IPdict = defaultdict(list)
    print 'parsing and converting IP-addresses to human-readable form'

    # Loop through every packet in pcap file
    for ts, buf in filetoparse:
#       session['message'] = tempIPlist
        packetnr += 1
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        # Data to be extracted from pcap file and stored in a list
        ip = eth.data
        do_not_fragment = bool(dpkt.ip.IP_DF)
        more_fragments = bool(dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        # Print packet data
        print 'IP: %s -> %s (len=%d ttl=%d DF=%d MF=%d offset=%d) %d\n' % \
            (ipsrc2human(ip.src), ipdest2human(ip.dst), ip.len, ip.ttl,
             do_not_fragment, more_fragments, fragment_offset, packetnr)

        # If packet is first packet then don't check if packet data has already been stored and store in tempIPlist and IPdict and start count
        if packetnr == 0:
            counter = counter + 1
            parsedIPs = [packetnr, str(ipsrc2human(ip.src)), str(ipdest2human(ip.dst)), str(
                ipsrc2human(ip.src)), str(ipdest2human(ip.dst)), shodansrc, shodandst]
            tempIPlist.extend(parsedIPs)
            IPdict[counter] = parsedIPs
            print 'packetnr is %d. Not already stored in list. Storing at IP-packet count: %d' % packetnr, packetnr

        # In case this is not the first packet
        else:

            #  and if packet data is already stored in tempIPlist then skip
            if ipsrc2human(ip.src) in tempIPlist and ipdest2human(ip.dst) in tempIPlist:
                print 'Already stored in list. Continueing from IP-packet count: %s' % packetnr
            # if packet data is not yet stored then store it by appending it to tempIPlist and IPdict
            else:
                counter = counter + 1
                parsedIPs = [packetnr, str(ipsrc2human(ip.src)), str(ipdest2human(ip.dst)), str(
                    ipsrc2human(ip.src)), str(ipdest2human(ip.dst)), shodansrc, shodandst]
                tempIPlist.extend(parsedIPs)
                IPdict[counter] = parsedIPs
                print 'Not already stored in list. Storing at IP-packet count: %d' % packetnr

    print '===== Converted IP-addresses to human-readable form'
    print '=== Datadump tempIPlist: %s \n' % tempIPlist
    print "= Resolving IP's into hostnames"

    # Loop through IPdict list and resolve the IP's
    for key in IPdict:
        IPdict[key][3] = resolveIP(IPdict[key][3])
        IPdict[key][4] = resolveIP(IPdict[key][4])
        print "Got %s \n Got %s" % (IPdict[key][3], IPdict[key][4])

    # Save list in session variable for shodan analysis
    session['parse'] = IPdict

    # Write json IP data as .json file in upload folder with case number (customer) as filename
    with open(os.path.join(UPLOAD_FOLDER) + 'shodan-json.json', 'w') as file:
        json.dump(IPdict, file)

    # When done return True to enterInfo()
    session.clear()
    return True

# Resolve IP to hostname function


def resolveIP(ip):
    try:
        hostname = socket.gethostbyaddr(ip)
        return hostname[0]
    except:
        hostname = ip
        return hostname

# Convert parsed source and destination IP into human-readable form


def ipsrc2human(addrsrc):
    return socket.inet_ntoa(addrsrc)


def ipdest2human(addrdest):
    return socket.inet_ntoa(addrdest)

# If DNS strings return as non-ASCII, convert them with this method


def hexify(x):
    "The strings from DNS resolver contain non-ASCII characters - I don't know why.  This function investigates that"
    def toHex(x): return "".join([hex(ord(c))[2:].zfill(2) for c in x])
    return toHex(x)

# Define allowed file extensions for uploading referring to ALLOWED_EXTENSIONS


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Make use of the reusable form


class ReusableForm(Form):
    name = TextField('Start Shodan lookup', validators=[validators.required()])


# Threaded = true is to solve problem of connection being terminated by host (probably not necessary in production)
if __name__ == "__main__":
    flaskapp.run(threaded=True)
