from flask import Flask, jsonify, abort, request, url_for
import redis
import json
import ssl
from hashlib import sha256
import logging
import os
import time
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import ipfshttpclient as ipfs
import pymongo
import bson.json_util as json_util
import requests
from base64 import b64encode, b64decode

IV = 'qt74bx0ns3t5kdra'
r = redis.Redis(host='0.0.0.0', port=6379)
ssl.match_hostname = lambda cert, hostname: True
app = Flask(__name__, static_url_path='/static')

os.environ['TZ'] = 'Asia/Calcutta'
time.tzset()

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

dbclient = pymongo.MongoClient()
db = dbclient['main']

class Ipfs:
    def __init__(self):
        self._client = ipfs.connect(session=True)

    def addjson(self, stuff):
        hassh = self._client.add_json(stuff)
        return hassh

    def close(self):
        self._client.close()

def generate_AES_key(num=32):
    return Random.new().read(num)

def encrypt_AES(msg, key):
    obj = AES.new(key, AES.MODE_CBC, IV)
    xlength = 16 - len(msg) % 16
    msg += ' ' * xlength # padding (multiple of 16)
    return obj.encrypt(msg)

def decrypt_AES(msg, key):
    obj = AES.new(key, AES.MODE_CBC, IV)
    message = obj.decrypt(msg).rstrip() # removing padding
    return message

def generate_RSA_keys():
    private_key = RSA.generate(1024)
    public_key = private_key.publickey()
    private_key = b64encode(private_key.exportKey())
    #private_key = private_key.exportKey().decode()
    public_key = b64encode(public_key.exportKey())
    return public_key, private_key

def encrypt_RSA(msg, public_key):
    public_key = RSA.importKey(b64decode(public_key))
    handler = PKCS1_OAEP.new(public_key)
    return handler.encrypt(msg.encode('utf-8'))

def decrypt_RSA(data, private_key):
    private_key = RSA.importKey(b64decode(private_key))
    handler = PKCS1_OAEP.new(private_key)
    return handler.decrypt(data)

@app.route('/users', methods=['POST', 'GET'])
def users():
    if request.method == 'POST':
        userdata = request.json

        logger.info('Username {}'.format(username))

        identifier = sha256((userdata['username'] + userdata['password']).encode('utf-8')).hexdigest()
        user = db['users'].find_one({'identifier' : identifier})

        if user is None:
            logger.info('{} : DB not hit. Creating user..'.format(userdata['username']))
            public, private = generate_RSA_keys()
            logger.info('{} : User public key produced..'.format(public))
            logger.info('{} : User private key produced..'.format(private))

            userdata['public'] = public
            userdata['private'] = private
            userdata['identifier'] = identifier
            db['users'].insert_one(userdata)

            public_user = {'username' : userdata['username'], 'public' : public}
            db['public_users'].insert_one(public_user)
            return jsonify({'status' : 'succesful'})
        else:
            logger.info('{} : DB hit'.format(username))
            user = json.loads(json_util.dumps(user))
            return jsonify({'data' : user})
    elif request.method == 'GET':
        identifier = request.args.get('identifier')
        user = db['users'].find_one({'identifier' : identifier})
        user = json.loads(json_util.dumps(user))
        return jsonify({'data' : user})


@app.route('/dir', methods=['GET'])
def dir():
    all_users = db['public_users'].find()
    all_users = json.loads(json_util.dumps(all_users))
    return jsonify({'data' : all_users})

@app.route('/test', methods=['GET'])
def test():
    data = requests.get('http://localhost:8080/dir')
    data = data.json()['data']
    data = data[-1]

    request_json = {"username": data['username'] , "password": "madlad" , "content" : {"title" : "Hello"}, "access" : [{"username" : data['username'], "public" : data['public']}]}

    #print('request')
    #print(request_json)
    print(request_json['access'][0]['public'])

    stuff = requests.post('http://localhost:8080/block', json=request_json)

    return jsonify({'status' : 'ok'})

@app.route('/block', methods=['POST', 'GET'])
def block():
    if request.method == 'POST':
        block = {}
        block['keys'] = []
        try:
            username = request.json['username']
            password = request.json['password']
            content = {'body' : request.json['content']}
            access = request.json['access'] # List of public keys that can access block [{username : , public : }, {}]
        except Exception as e:

            return jsonify({'status' : 'error'})
            print(e)


        logger.info('Username {}'.format(username))

        identifier = sha256((username + password).encode('utf-8')).hexdigest()
        user = db['users'].find_one({'identifier' : identifier})
        
        if not user:
            logger.error({'error' : 'User does not exist'})
            return jsonify({'error' : 'User does not exist'})

        user = json.loads(json_util.dumps(user))

        AES_key = generate_AES_key()
        encrypted_data = encrypt_AES(json.dumps(content), AES_key)

        ipfs_client = Ipfs()
        IPFS_hash = ipfs_client.addjson(content)
        logger.info("Content added on IPFS hash : {}".format(IPFS_hash))
        block['ipfs'] = IPFS_hash
        #block['content'] = encrypted_data
        block['content'] = content
        block['title'] = "Data entry by {}".format(username)
        block['owner'] = user['identifier'] 

        logger.info('IPFS hash {}'.format(IPFS_hash))
        a = access[0]

        #for a in access:
        RSA_KEY = (a['public']['$binary'])
        #print(a['public'])
        AES_key = 'hello world'
        #print(RSA_KEY)
        #print('\n\n\n')
        #print(AES_key)
        #key = encrypt_RSA(AES_key, RSA_KEY)
        key = 'xyzyzyzyzyzzy'
        print(key)
        block['keys'].append({'username' :a['username'], 'AES_Key' : key})

        logger.info('Adding block..')
        logger.info(block)
        db['blocks'].insert_one(block)

        #print(block)

        return jsonify({'status' : 'success'})

    elif request.method == 'GET':
        identifier = request.args.get('identifier')
        block = db['blocks'].find_one({'owner' : identifier})
        block = json.loads(json_util.dumps(block))
        return jsonify({'data' : block})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
