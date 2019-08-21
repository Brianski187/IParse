Web-App for automation of extracting, parsing and looking up IP addresses contained in a Pcap file.

Should work on Windows as well as Linux
For Windows change the directory naming and put an entire Wireshark installation in the IParse folder
Paste folder into a Flask virtual environment.

(Linux)
1:
-> pip install Flask, venv, dpkt, pyshark-legacy, json2html, python-pcapng

2:
Get a Shodan API key and add it to the SHODAN_API_KEY variable app.py.

3:
Add a secret key in app.py variable flaskapp.secret_key = '%secret-key%'

4:
Edit the UPLOAD_FOLDER directory to yours in app.py: UPLOAD_FOLDER = '%/root/?/?/?/IParse/uploads/%'

5:
-> cd ../venv
-> . /bin/activate
-> cd %project-map%
-> python app.py

6:
In a browser enter 127.0.0.1:5000 and follow the instructions


(%bla% == user input)
(Feedback of app process in Terminal)
