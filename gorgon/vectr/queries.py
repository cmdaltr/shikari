#!/usr/bin/env python3 -tt
import requests


def send_request(vectr_url, vectr_headers, query):
    return requests.post(
        vectr_url,
        headers=vectr_headers,
        json={"query": query},
        verify=False,
    )


def get_indicies(vectr_url, vectr_headers):
    return ["FS_THREAT_INDEX", "HEALTH_THREAT_INDEX"]
    indexed_assessments = {}
    query = """
    query {
    databases {
        name
        }
    }
    """

    response = send_request(vectr_url, vectr_headers, query)
    indicies = [db["name"] for db in response["data"]["databases"]]
    for index in indicies:
        assessments = get_assessments(vectr_url, vectr_headers, index)
    for index in indicies:
        if index == "FS_THREAT_INDEX":
            assessments = [
                "Financial Services Threat Index (Q1)",
                "Financial Services Threat Index (Q2)",
                "Financial Services Threat Index (Q3)",
                "Financial Services Threat Index (Q4)",
            ]
        elif index == "HEALTH_THREAT_INDEX":
            assessments = [
                "Health Threat Index 2022 (Q1)",
                "Health Threat Index 2022 (Q2)",
                "Health Threat Index 2022 (Q3)",
                "Health Threat Index 2022 (Q4)",
            ]
        indexed_assessments[index] = assessments

    return indexed_assessments


def get_assessments(vectr_url, vectr_headers, index):
    return [
        {
            "data": {
                "assessments": {
                    "nodes": [
                        {
                            "id": "1",
                            "name": "Financial Services Threat Index (Q1)",
                            "description": "Q1 - Financial Services Threat Index",
                            "createTime": 1640995201000.0,
                        },
                        {
                            "id": "2",
                            "name": "Financial Services Threat Index (Q2)",
                            "description": "Q2 - Financial Services Threat Index",
                            "createTime": 1648771201000.0,
                        },
                        {
                            "id": "3",
                            "name": "Financial Services Threat Index (Q3)",
                            "description": "Q3 - Financial Services Threat Index",
                            "createTime": 1656633601000.0,
                        },
                        {
                            "id": "4",
                            "name": "Financial Services Threat Index (Q4)",
                            "description": "Q4 - Financial Services Threat Index",
                            "createTime": 1664582401000.0,
                        },
                        {
                            "id": "9",
                            "name": "plump",
                            "description": "blahblah",
                            "createTime": 1750857004960.0,
                        },
                        {
                            "id": "10",
                            "name": "plump2",
                            "description": "blahblah",
                            "createTime": 1750857342762.0,
                        },
                        {
                            "id": "11",
                            "name": "test",
                            "description": "blahblah",
                            "createTime": 1750857383135.0,
                        },
                    ]
                }
            }
        }
    ]
    query = """
    query {
    assessments(db: "{}") {
        nodes {
        id
        name
        description
        }
    }
    }
    """.format(
        index
    )

    response = send_request(vectr_url, vectr_headers, query)
    return [
        assessment["name"] for assessment in response["data"]["assessments"]["nodes"]
    ]


def get_campaigns(vectr_url, vectr_headers, index):
    return [
        {"id": "15", "name": "Collection"},
        {"id": "26", "name": "Collection"},
        {"id": "4", "name": "Collection"},
        {"id": "37", "name": "Collection"},
        {"id": "30", "name": "Command and Control"},
        {"id": "8", "name": "Command and Control"},
        {"id": "41", "name": "Command and Control"},
        {"id": "19", "name": "Command and Control"},
        {"id": "22", "name": "Credential Access"},
        {"id": "11", "name": "Credential Access"},
        {"id": "44", "name": "Credential Access"},
        {"id": "33", "name": "Credential Access"},
        {"id": "6", "name": "Defense Evasion"},
        {"id": "39", "name": "Defense Evasion"},
        {"id": "17", "name": "Defense Evasion"},
        {"id": "28", "name": "Defense Evasion"},
        {"id": "31", "name": "Discovery"},
        {"id": "9", "name": "Discovery"},
        {"id": "20", "name": "Discovery"},
        {"id": "42", "name": "Discovery"},
        {"id": "13", "name": "Execution"},
        {"id": "35", "name": "Execution"},
        {"id": "24", "name": "Execution"},
        {"id": "2", "name": "Execution"},
        {"id": "12", "name": "Exfiltration"},
        {"id": "34", "name": "Exfiltration"},
        {"id": "23", "name": "Exfiltration"},
        {"id": "1", "name": "Exfiltration"},
        {"id": "25", "name": "Impact"},
        {"id": "14", "name": "Impact"},
        {"id": "3", "name": "Impact"},
        {"id": "36", "name": "Impact"},
        {"id": "38", "name": "Initial Access"},
        {"id": "5", "name": "Initial Access"},
        {"id": "16", "name": "Initial Access"},
        {"id": "27", "name": "Initial Access"},
        {"id": "18", "name": "Lateral Movement"},
        {"id": "40", "name": "Lateral Movement"},
        {"id": "7", "name": "Lateral Movement"},
        {"id": "29", "name": "Lateral Movement"},
        {"id": "21", "name": "Persistence"},
        {"id": "43", "name": "Persistence"},
        {"id": "10", "name": "Persistence"},
        {"id": "32", "name": "Persistence"},
    ]
    query = """
    query {
    campaigns(db: {}) {
        nodes {
        id
        name
        }
    }
    }
    """.format(
        index
    )

    response = send_request(vectr_url, vectr_headers, query)
    return [
        {"id": campaign["id"], "name": campaign["name"]}
        for campaign in response["data"]["campaigns"]["nodes"]
    ]


def get_testcase_templates(vectr_url, vectr_headers):
    return "Y"
    query = """
    query {
    libraryTestcases {
        nodes {
        id
        name
        }
    }
    }
    """

    response = send_request(vectr_url, vectr_headers, query)
    templates = response["data"]["libraryTestcases"]["nodes"]
    matching = [
        template
        for template in templates
        if template["name"] == "Basic Phishing Template"
    ]

    if matching:
        return "Y"
    else:
        return "N"


def get_orgs(vectr_url, vectr_headers):
    return [
        {"id": "92fa723f-7791-467f-8726-05d34d80f40f", "name": "MITRE"},
        {"id": "f1f60f50-6564-4ce4-a376-4e6d9bac8183", "name": "Red Canary"},
        {
            "id": "1cf413ba-326a-4d18-979c-367eb1306f69",
            "name": "Security Risk Advisors",
        },
    ]
    query = """
    query {
    organizations {
        nodes {
        id
        name
        }
    }
    }
    """

    response = send_request(vectr_url, vectr_headers, query)
    return [
        {"id": org["id"], "name": org["name"]}
        for org in response["data"]["orginizations"]["nodes"]
    ]


def get_phases(vectr_url, vectr_headers):
    return [
        {"id": "0d594ca4-4491-4b70-9227-c9e0589dfcca", "name": "Action on Objectives"},
        {"id": "24291ae1-2110-4f4c-8b0d-7b8c8676ed5d", "name": "Collection"},
        {"id": "69a00d73-ea90-401c-8ef0-9fcd1785d0b4", "name": "Command & Control"},
        {"id": "01d77cc8-b129-413b-adf5-850cebc4ae79", "name": "Credential Access"},
        {"id": "cc4c7093-0b33-4cf6-95a7-eff607c86c79", "name": "Defense Evasion"},
        {"id": "b01606fb-b984-4415-ac33-456e12fecea9", "name": "Delivery"},
        {"id": "549e7bc3-0b2b-46bc-a6d7-81bf0679c1b3", "name": "Discovery"},
        {"id": "772a480f-21d2-4d3b-bc7d-ef9ac82fc46b", "name": "Execution"},
        {"id": "bb51fb2c-dc2f-40dc-9e1b-f3f33f7d5675", "name": "Exfiltration"},
        {"id": "1b7512d2-ec31-4fab-af57-4fec213b0ae8", "name": "Exploitation"},
        {"id": "5f453ab7-7447-4d48-85bb-c092111b10a5", "name": "Impact"},
        {
            "id": "ea484b54-b28a-48cc-b5b3-5e469e06c466",
            "name": "Impair Process Control",
        },
        {
            "id": "fdc77b3b-5ec4-4a08-af36-a84db87fbb08",
            "name": "Inhibit Response Function",
        },
        {"id": "769c1759-3db5-486d-918a-67fbadee4787", "name": "Initial Access"},
        {"id": "866d6b69-3f03-4c88-bf51-679a0e4cab74", "name": "Lateral Movement"},
        {"id": "32af5159-9e19-4a40-a7cc-f5172b11c7b8", "name": "Network Effects"},
        {"id": "47da3f56-d9fc-4735-a343-b57b4ad8eca5", "name": "Persistence"},
        {"id": "ecef1af6-4ab3-4501-a94c-9d72bd72f124", "name": "Pivoting"},
        {"id": "48dc2baf-1d23-46cb-bb6f-ef36bc0db493", "name": "Privilege Escalation"},
        {"id": "ac8d65ca-f067-4213-9383-ac34dc8f236c", "name": "Reconnaissance"},
        {
            "id": "6979ffd8-882e-490e-b034-5b0cb5002a06",
            "name": "Remote Service Effects",
        },
        {"id": "4e9f4e55-bbcd-448a-9b6c-d470eeb04793", "name": "Resource Development"},
        {"id": "f9271ade-7cab-4cba-9a3e-6f722482bb80", "name": "Social Engineering"},
        {"id": "7ff406ce-85e1-4732-ae3d-8ec478023d6f", "name": "Target Manipulation"},
        {"id": "2afb7c56-ea1b-47fc-b96c-1579dd049690", "name": "Weaponization"},
    ]

    query = """
    query {
    phases {
        nodes {
        id
        name
        }
    }
    }
    """

    response = send_request(vectr_url, vectr_headers, query)
    return [
        {"id": phase["id"], "name": phase["name"]}
        for phase in response["data"]["phases"]["nodes"]
    ]


def get_redtools(vectr_url, vectr_headers):
    return [
        {"id": "7b860960-e619-4341-96ad-a05d46335606", "name": "Acunetix"},
        {"id": "1e0b019e-f72d-49d9-809c-13179d1050dc", "name": "AdFind"},
        {"id": "6fb29093-75dd-413b-8c15-a95cf5c63f7a", "name": "Azure CLI"},
        {"id": "1da4aad6-7f01-4e4f-9145-b9be54ce162a", "name": "BloodHound"},
        {"id": "77131dd4-f6b1-46eb-8b8a-5e32a7b7f907", "name": "BurpSuite"},
        {"id": "73cf6e51-e5fd-4502-80bc-c15f2016d6be", "name": "C3"},
        {"id": "cd1fc0ee-e22c-4c70-ae00-642b26146aa1", "name": "CSPY Downloader"},
        {"id": "9d8e81e7-127f-464e-8671-bfdc6cced3d5", "name": "Cobalt Strike"},
        {"id": "398b89e4-9b98-4d8f-b232-d8e7dd5c2317", "name": "ConnectWise"},
        {"id": "52817322-cece-405e-a05e-7c785b57629b", "name": "CrackMapExec"},
        {"id": "b2ad71b5-de3f-4a1b-a273-adeefa579842", "name": "CredBandit"},
        {"id": "26e032e7-d3bb-0950-7b74-7628a3be232c", "name": "CredNinja"},
        {"id": "122fd761-c03b-b8dd-3536-b63ffee3797e", "name": "DET"},
        {"id": "94c81405-fddc-49d8-92d0-fef3d076238b", "name": "Dameware"},
        {"id": "d21dfd93-7a14-460e-8e5e-b359df63dfc0", "name": "Dumpert"},
        {"id": "e5b333cd-f67d-4fa1-aa8f-7e6778acd851", "name": "Ebowla"},
        {"id": "964d9ac4-68b8-9047-3d98-fcee515d4a2a", "name": "Egress Buster"},
        {"id": "f7888f6f-bf0d-ec77-6e70-3a3146e15fed", "name": "Egress-Assess"},
        {"id": "76ca4ddf-5174-57a7-2842-70d5af62a25c", "name": "Empire"},
        {"id": "23e621a0-64a2-a319-2260-1350eb8ca4dc", "name": "Evasion"},
        {"id": "001ff422-5ce9-9680-42ab-fe0247831238", "name": "FTP"},
        {"id": "ef895acd-2ddd-ecd3-fe17-97b4916a04a9", "name": "Get-GPPPassword"},
        {"id": "a636a63a-c1ec-4e9d-bb0a-5a2d31f8d82a", "name": "Imminent Monitor"},
        {"id": "e53ed1f5-5c1d-4590-a3ab-58b8457ad2ab", "name": "Impacket"},
        {"id": "92d43839-aa3e-3791-1dc9-9b944eb55a84", "name": "Instegogram"},
        {"id": "9c409097-af9f-419c-84f9-f816b0cf81fc", "name": "Invoke-PSImage"},
        {"id": "de463005-5294-471e-9207-160f9b73a950", "name": "IronNetInjector"},
        {"id": "f7f4c82b-de35-40f6-ae90-ea067bfd9f7d", "name": "JackIt"},
        {"id": "1cff6cf2-ae3d-45d1-82d5-3c8909e1ce2f", "name": "Koadic"},
        {"id": "ebcb5873-088f-4b6a-8e36-36bcd91b87c3", "name": "LaZagne"},
        {"id": "d9ccbd68-13f8-43de-91e6-22ace3b31a8b", "name": "Lslsass"},
        {"id": "94f2afb5-5938-4e3d-9487-24ba710b6284", "name": "MCMD"},
        {"id": "0e5f367a-d03b-4e88-bc2c-05e4bf6e3a0b", "name": "MEGA"},
        {"id": "99bf8112-140e-d155-9f0e-7a7b0136065f", "name": "MMC"},
        {"id": "e9272f89-cc24-433e-a3c4-dae3358c891b", "name": "MSXSL"},
        {"id": "12c98550-4c65-40c8-8ab0-b74c33ced1ac", "name": "MailSniper"},
        {"id": "4134a48a-87f8-6a59-c5f0-e238c3c8615e", "name": "Manual Techniques"},
        {"id": "dfa46a7d-0580-4acd-bab7-250212b49a1d", "name": "Metasploit"},
        {"id": "3883d65a-3ad2-4111-92fa-19a5d39a119d", "name": "Mimikatz"},
        {
            "id": "96ebaac5-a28f-7b75-4044-bc18a4faa93e",
            "name": "Native Windows Commands",
        },
        {"id": "f6b6f2d9-74a5-4d54-ad70-d08a1907e9f7", "name": "Nessus"},
        {"id": "f31c1e27-8bec-45f9-9721-4f3e83be3a18", "name": "Net"},
        {"id": "edb2756b-1379-3c6f-5cc8-24046e3a69b5", "name": "Netcat"},
        {"id": "7445464e-d222-40cb-b187-8c9f0c08ac0e", "name": "Nmap"},
        {"id": "44a480e9-ed71-7dba-213b-532912319036", "name": "Oscanner"},
        {"id": "072a2b36-87cf-4b39-8a07-1682edd28505", "name": "Out1"},
        {"id": "c714dacc-e757-e64f-880a-d0c3f2bde44c", "name": "PSExec"},
        {"id": "7aa349f8-241d-429a-aa0f-b21f5a522124", "name": "Pass-The-Hash Toolkit"},
        {"id": "9bde2969-8d68-4e0c-960c-ef192d9a1e20", "name": "PoshC2"},
        {"id": "bc5080df-ad46-8c5a-9f23-12f61d2ec5e6", "name": "PowerShell"},
        {"id": "8c7c0430-7b82-4a2b-9c6a-e72a6182c206", "name": "PowerSploit"},
        {"id": "cc970060-2c46-4e07-abd6-9a4e6b95d3d4", "name": "PowerUp"},
        {"id": "e370d9bf-6ecc-0b35-4675-d8d4232b98e0", "name": "PowerView"},
        {"id": "a697522d-06b3-03bf-bcfa-39cb345412cd", "name": "ProcDump"},
        {"id": "856fa9c6-44c4-4a18-9333-051a1952559f", "name": "PsExec"},
        {"id": "73bc3327-18c3-40a6-94b5-82d894ef1fb9", "name": "Pupy"},
        {"id": "1558a333-be50-4e30-ae69-88a7bd73b473", "name": "QuasarRAT"},
        {"id": "07da0703-151c-4377-a940-68890145e72d", "name": "RawDisk"},
        {"id": "ca509c6a-0961-411d-9374-40982c057f65", "name": "RemCom"},
        {"id": "92d751b8-f5eb-4e10-99df-7fbb44504465", "name": "Remcos"},
        {"id": "2a13db19-5430-49ae-abf2-551824aefd87", "name": "Responder"},
        {"id": "b7e5a791-18e2-40a0-ae39-94b2e339dda6", "name": "Rubeus"},
        {"id": "e2ad2a59-22a3-05d7-197a-23bdcc44d673", "name": "SMB"},
        {"id": "69e0c9d9-fdc4-49ae-8f84-8ed93b0bde80", "name": "SMBexec"},
        {"id": "57367a9f-1ad7-4c7d-b2a9-068185e812c5", "name": "SQL Server Manager"},
        {"id": "cc8d129b-9dec-ea1f-eb65-4d491c80a2df", "name": "SQLping3"},
        {"id": "240a9859-5fe4-28e1-d88a-7d4ed2e649bd", "name": "SSH"},
        {"id": "43622db9-177b-450f-8419-2d649f95700b", "name": "SafetyKatz"},
        {"id": "e7247703-c6d5-4615-bee0-30d0bc9b479a", "name": "Scout Suite"},
        {"id": "10cae1a0-197b-4d13-81df-13ee5462e289", "name": "ScouteSuite"},
        {"id": "3e4eb553-6396-2122-edb8-3762574f2521", "name": "ShareEnum"},
        {"id": "cf2e1c06-d7f9-4fcb-931e-f85372a32c61", "name": "SharpChrome"},
        {"id": "0fe26afc-752a-4446-8e42-3e5afd997528", "name": "SharpDump"},
        {"id": "84b07f20-f903-4bd1-9dc0-00a0b1909af3", "name": "ShimRatReporter"},
        {"id": "2abf20a9-f6a5-497c-a4fb-1d5cb0d534f7", "name": "Sliver"},
        {"id": "00ab62fe-c4e8-4105-ac5f-26d23a93cc32", "name": "SubBrute"},
        {"id": "8bf38aa9-5dcb-4a85-876b-b4e0c93452c9", "name": "Tasklist"},
        {"id": "05a1cd00-744e-401c-af6d-47579d5ce57a", "name": "TeamViewer"},
        {"id": "7110e989-7a07-d45a-e680-7273e3831b7e", "name": "Telnet"},
        {"id": "7c92ce89-bd96-46d4-9843-a6fc8f35567a", "name": "Tor"},
        {"id": "68669683-8d6b-4051-bf7a-ddcf6ff40b66", "name": "Tor Browser"},
        {"id": "cb94560f-2123-4c0a-99e9-a23de34004f5", "name": "VNC"},
        {"id": "9f434613-62d3-4cb3-b8de-86983925d339", "name": "WeirdAAL"},
        {
            "id": "3e0795bb-5ca4-4c03-953f-efa2530c26ba",
            "name": "Windows Credential Editor",
        },
        {"id": "a63ca7bb-411c-4f25-94be-a77ba638379c", "name": "Winexe"},
        {"id": "b93633b9-0ac3-4ac3-8f05-a3c29a4944ca", "name": "at"},
        {"id": "e79cbc9c-3e73-4428-bf8a-345b952d26e1", "name": "blahblah"},
        {"id": "a57e20f1-4583-4bdc-b7d7-12d72c8c5ebf", "name": "cmd"},
        {"id": "7d7a19a1-d7c9-40dc-9327-d7f2631086c5", "name": "dsquery"},
        {"id": "a390cc3a-72b8-4c86-84ac-099a2ed09a81", "name": "esentutl"},
        {"id": "28659d9d-3a28-4d04-9e88-c9152c972117", "name": "ftp"},
        {"id": "91748905-7933-4fa3-83a0-4467ba29e6ea", "name": "gsecdump"},
        {
            "id": "8bff5715-23c1-4e8e-8898-c1d48fefba31",
            "name": "https://aadinternals.com/aadinternals/",
        },
        {
            "id": "a647efdc-2d7c-4e8b-adc1-3ec6fab2753a",
            "name": "https://github.com/2XXE-SRA/payload_resources/blob/master/batch/apt41.bat",
        },
        {
            "id": "dfa03157-34e2-48e0-97c1-c32d7b203980",
            "name": "https://github.com/2XXE-SRA/payload_resources/blob/master/batch/bazar_adf.bat",
        },
        {
            "id": "06b77506-9c33-4483-aa92-7514ed1f05b8",
            "name": "https://github.com/2XXE-SRA/payload_resources/blob/master/dll/odbcconf.rsp",
        },
        {
            "id": "e95d2ede-6df6-48b2-9794-0d9a550065c1",
            "name": "https://github.com/2XXE-SRA/payload_resources/tree/master/coldencryptor",
        },
        {
            "id": "3298e504-040c-4050-849e-8c1a5df5aeb4",
            "name": "https://github.com/Arvanaghi/SessionGopher",
        },
        {
            "id": "d46f3d49-67f5-4e5a-9229-a0e33430e64a",
            "name": "https://github.com/GhostPack/Rubeus",
        },
        {
            "id": "fc1d1bff-bbb9-415d-8671-b76d13ea4b9f",
            "name": "https://github.com/GhostPack/SharpDPAPI",
        },
        {
            "id": "e20cf6ee-a424-4efa-9116-ded1cc152dc5",
            "name": "https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer",
        },
        {
            "id": "d9e1b820-87be-436b-bf57-bbf139401789",
            "name": "https://learn.microsoft.com/en-us/sysinternals/downloads/procdump",
        },
        {
            "id": "5658811b-c1aa-46c5-90f0-e391c8ef48d9",
            "name": "https://nordvpn.com/download/",
        },
        {
            "id": "62b7744a-e86b-4fef-9978-3630ed730f00",
            "name": "https://processhacker.sourceforge.io/",
        },
        {"id": "4de4bf48-13f2-4eaf-9a1e-2e8dd736a5e5", "name": "https://rclone.org/"},
        {
            "id": "146ebf25-8382-4d17-88a1-07847d72ea66",
            "name": "https://www.7-zip.org/download.html",
        },
        {
            "id": "41b230d1-86de-4c64-a110-5812de621015",
            "name": "https://www.softperfect.com/products/networkscanner/",
        },
        {"id": "f3b79aed-418a-402d-ba68-2b87646f50f5", "name": "meek"},
        {"id": "c33e1459-5a55-4e00-9871-344138d1dcda", "name": "netsh"},
        {"id": "27b2d392-a1b6-45e8-984e-546a2fb282b1", "name": "nmap"},
        {"id": "fd4d764d-bc07-471d-8826-0acb7a7a6fcc", "name": "procdump"},
        {"id": "b9a45c70-7997-46f6-b9da-3fa87762582b", "name": "pwdump"},
        {"id": "ee862499-956a-4fa7-8bc2-6ce995a0a985", "name": "schtasks"},
        {"id": "5f26c0dd-4f68-4395-a1e0-21768ed675f6", "name": "spwebmember"},
        {"id": "f9745f2c-f6f2-4401-8dac-1a59f75903e4", "name": "sqlmap"},
        {"id": "a09e134b-c18a-48bd-9055-f938c9b7c5a5", "name": "sqlninja"},
    ]
    query = """
    query {
    libraryRedtools {
        nodes {
        id
        name
        }
    }
    }
    """

    response = send_request(vectr_url, vectr_headers, query)
    return [
        {"id": libraryredtool["id"], "name": libraryredtool["name"]}
        for libraryredtool in response["data"]["libraryRedtools"]["nodes"]
    ]
