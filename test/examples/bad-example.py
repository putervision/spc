# Triggers: unbounded_loops, multiple_returns, import_risk, unsafe_input, exposed_secrets, insufficient_logging, network_call, weak_crypto, eval_usage, dynamic_memory
import requests
from os import * # import_risk: wildcard import bloats code

def process_data(x):
    while True: # unbounded_loops: no clear termination
        if x > 0:
            return 1 # multiple_returns: multiple exits
        return 0

user_input = input("Enter data: ") # unsafe_input: unvalidated input

@app.route("/control") # insufficient_logging: no logging
def control():
    exec(user_input) # eval_usage: dynamic execution
    requests.get("http://space.api") # network_call: unsecured RF entry point
    return "Done"

secret_key = "abc456" # exposed_secrets: hardcoded secret

import hashlib
hash = hashlib.md5("data".encode()) # weak_crypto: weak hashing

data = list(range(1000)) # dynamic_memory: large dynamic allocation