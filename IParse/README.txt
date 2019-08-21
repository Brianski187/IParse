Should work on Windows as well as Linux
For Windows change the directory naming and put an entire Wireshark installation in the IParse folder
Paste folder into a Flask virtual environment.
-> pip install Flask, venv, dpkt, pyshark-legacy, json2html, python-pcapng

Get a Shodan API key and add it to the SHODAN_API_KEY variable app.py.
Add a secret key in app.py variable flaskapp.secret_key = '%secret-key%'
Edit the UPLOAD_FOLDER directory to yours in app.py: UPLOAD_FOLDER = '%/root/?/?/?/IParse/uploads/%'

-> cd ../venv
-> . /bin/activate
-> cd %project-map%
-> python app.py

In a browser enter 127.0.0.1:5000 and follow the instructions

(%bla% == user input)
(Feedback in Terminal)

