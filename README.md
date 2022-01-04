#IParse

## Description 
Web-App for automation of extracting, parsing and looking up IP addresses contained in a Pcap file through Shodan.

Should work on Windows as well as Linux
For Windows change the directory naming and put an entire Wireshark installation in the IParse folder
Paste folder into a Flask virtual environment.

(Linux)
1:
Unzip bootstrap in IParse/static/

2:
```
pip install Flask 
pip install dpkt
pip install pyshark-legacy
pip install json2html
pip install python-pcapng
pip install venv
```

3:
Get a Shodan API key and add it to the SHODAN_API_KEY variable app.py.

4:
Add a secret key in app.py variable flaskapp.secret_key = '%secret-key%'

5:
Edit the UPLOAD_FOLDER directory to yours in app.py: 
```
UPLOAD_FOLDER = '%/root/?/?/?/IParse/uploads/%'
```

6:
```
cd ../venv
. /bin/activate
cd %project-map%
python app.py
```
7:
In a browser enter 127.0.0.1:5000 and follow the instructions


(%bla% == user input)
(Feedback of app process in Terminal)
