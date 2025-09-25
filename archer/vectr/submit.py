#!/usr/bin/env python3 -tt
import subprocess


def generate_curl_command(instance, port, endpoint, api_key, secret_key, payload):
    return (
        f"curl -k -X POST https://{instance}:{port}{endpoint} "
        f'-H "Authorization: VEC1 {api_key}:{secret_key}" '
        '-H "Content-Type: application/json" '
        '-d \'{"query": "query { ' + payload
    )


def submit_testcase(curl_command):
    try:
        result = subprocess.run(
            curl_command,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        print("cURL command executed successfully.")
        print("Response:")
        print(result.stdout.decode())
    except subprocess.CalledProcessError as e:
        print("Error executing cURL command:")
        print(e.stderr.decode())
        print("Return code:", e.returncode)
        print("Command output:", e.output.decode())
        print("Command was:", curl_command)
