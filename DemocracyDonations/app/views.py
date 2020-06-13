import datetime
import json
import webbrowser

import requests
from flask import render_template, redirect, request, url_for

from app import app

# The node with which our application interacts, there can be multiple
# such nodes as well.
CONNECTED_NODE_ADDRESS = "http://0.0.0.0:8000"

posts = []


def fetch_posts():
    """
    Function to fetch the chain from a blockchain node, parse the
    data and store it locally.
    """
    get_chain_address = "{}/chain".format(CONNECTED_NODE_ADDRESS)
    response = requests.get(get_chain_address)
    if response.status_code == 200:
        content = []
        chain = json.loads(response.content)
        for block in chain["chain"]:
            for tx in block["transactions"]:
                tx["index"] = block["index"]
                tx["hash"] = block["previous_hash"]
                content.append(tx)

        global posts
        posts = sorted(content, key=lambda k: k['timestamp'],
                       reverse=True)


@app.route('/')
def index():
    fetch_posts()
    return render_template('index.html',
                           title='Democracy Donations: Transparent politics',
                           posts=posts,
                           node_address=CONNECTED_NODE_ADDRESS,
                           readable_time=timestamp_to_string)

@app.route('/democracyDollars')
def democracyDollars():
    return render_template('democracyDollars.html',
                           title='Democracy Dollars Fund: Helping everyone be heard! ',
                           node_address=CONNECTED_NODE_ADDRESS,
                           readable_time=timestamp_to_string)

@app.route('/donations')
def landing():
    fetch_posts()
    return render_template('donations.html',
                           title='All donations made to Democracy Dollars',
                           posts=posts,
                           node_address=CONNECTED_NODE_ADDRESS,
                           readable_time=timestamp_to_string )

@app.route('/BlockchainData')
def getChain():
    return redirect("{}/chain".format(CONNECTED_NODE_ADDRESS))


@app.route('/submit', methods=['POST'])
def submit_textarea():
    """
    Endpoint to create a new transaction via our application.
    """
    post_content = request.form["content"]
    firstName = request.form["firstName"]
    lastName = request.form["lastName"]
    donorEmail = request.form["donorEmail"]
    donorAddress = request.form["donorAddress"]
    donorZip = request.form["donorZip"]
    donorPhone = request.form["donorPhone"]
    donation = request.form["donation"]
    fund = request.form["fund"]
    campaign = request.form["campaign"]
    

    post_object = {
        'content': post_content,
        'firstName': firstName,
        'lastName': lastName,
        'donorEmail': donorEmail,
        'donorAddress': donorAddress,
        'donorZip': donorZip,
        'donorPhone': donorPhone,
        'donation': donation,
        'fund': fund,
        'campaign': campaign
    }

    # Submit a transaction
    new_tx_address = "{}/new_transaction".format(CONNECTED_NODE_ADDRESS)

    requests.post(new_tx_address,
                  json=post_object,
                  headers={'Content-type': 'application/json'})

    webbrowser.open_new_tab("{}/mine".format(CONNECTED_NODE_ADDRESS))
    return redirect("/")

def timestamp_to_string(epoch_time):
    return datetime.datetime.fromtimestamp(epoch_time).strftime('%H:%M')
