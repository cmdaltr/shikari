from gorgon.vectr.queries import (
    get_assessments,
    get_campaigns,
    get_indicies,
    get_orgs,
    get_phases,
    get_redtools,
    get_testcase_templates,
    send_request,
)
from dotenv import load_dotenv
import getpass
import json
import os
import time


# Enviornment variables
load_dotenv(dotenv_path="gorgon/vectr/.env")
api_key = os.getenv("API_KEY")
secret = os.getenv("SECRET")
instance = os.getenv("INSTANCE")
port = os.getenv("PORT")
endpoint = os.getenv("ENDPOINT")
sources_to_choose = json.loads(os.getenv("SOURCES"))

# VECTR variables
vectr_url = f"https://{instance}:{port}/{endpoint}"
vectr_headers = {
    "Authorization": f"VEC1 {api_key}:{secret}",
    "Content-Type": "application/json",
}
indicies = get_indicies(vectr_url, vectr_headers)
orgs_in_vectr = get_orgs(vectr_url, vectr_headers)
phases_in_vectr = get_phases(vectr_url, vectr_headers)  # campaigns and tactics
redtools_in_vectr = get_redtools(vectr_url, vectr_headers)
orgs = []
for org_in_vectr in orgs_in_vectr:
    orgs.append(org_in_vectr.get("name"))

phases = []
for vectr_phase in phases_in_vectr:
    phases.append(vectr_phase.get("name"))


def do_assessment(assessments_in_vectr, assessment):
    for assessment_in_vectr in assessments_in_vectr:
        if assessment.lower() == assessment_in_vectr["name"].lower():
            return str([{"id": assessment_in_vectr["id"], "name": assessment}])


def do_campaign(campaigns_in_vectr, campaign):
    for campaign_in_vectr in campaigns_in_vectr:
        if campaign.lower() == campaign_in_vectr["name"].lower():
            return str([{"id": campaign_in_vectr["id"], "name": campaign}])


def do_org(orgs_in_vectr, chosen_org):
    # convert to dict with id of org name (else create new one) - need to perform curl query; then convert to list
    for org in orgs_in_vectr:
        if chosen_org.lower() == org["name"].lower():
            return str([{"id": org["id"], "name": chosen_org}])


def do_phase(phases_in_vectr, phaseName):
    # formatting phases (tactics); matching user input with existing vectr data
    for phase_in_vectr in phases_in_vectr:
        if phaseName.lower() == phase_in_vectr["name"].lower():
            return str([{"id": phase_in_vectr["id"], "name": phaseName}])


def do_redtools(redtools_in_vectr, redTools):
    # formatting redToolsName; matching user input with existing vectr data and creating new redtool if required
    redToolsName = []
    for redtool in redTools:
        provided_redtool = redtool.strip()
        if provided_redtool.lower() in str(redtools_in_vectr).lower():
            for redtool_in_vectr in redtools_in_vectr:
                if provided_redtool.lower() == redtool_in_vectr["name"].lower():
                    redToolsName.append(
                        {"id": redtool_in_vectr["id"], "name": provided_redtool}
                    )
        else:
            # cannot create new red tool
            print(
                f"\t'{provided_redtool}' does not exist in VECTR and cannot be created via the API.\n\tSee README.md for more information."
            )
            time.sleep(2)
    return str(redToolsName)


def do_detectionGuidance(detectionGuidance):
    return str(detectionGuidance)[2:-2].split("', '")


def create_assessment(
    vectr_url, vectr_headers, index, assessmentName, assessmentHypothesis, orgId
):
    return 12
    # hardcoded Unified Kill Chain id
    query = json.dumps(
        {
            "query": """
            mutation ($input: CreateAssessmentInput!) {
                assessment {
                    create(input: $input) {
                        assessments {
                            id
                            name
                            description
                            createTime
                        }
                    }
                }
            }
        """,
            "variables": {
                "input": {
                    "db": f"{index}",
                    "assessmentData": [
                        {
                            "name": f"{assessmentName}",
                            "description": f"{assessmentHypothesis}",
                            "organizationIds": f"{orgId}",
                            "killChainId": "ea965f5a-2a80-4a94-968e-740e70a80c90",
                        }
                    ],
                }
            },
        }
    )

    response = send_request(vectr_url, vectr_headers, query)
    if "Assessment already exists" in str(response) and "ValidationError" in str(
        response
    ):
        assessments_in_vectr = get_assessments(vectr_url, vectr_headers, index)
        assessmentId = do_assessment(assessments_in_vectr, assessmentName)
    else:
        assessmentId = response["data"]["assessment"]["create"]["assessments"][0]["id"]

    return assessmentId


def create_campaign(vectr_url, vectr_headers, index, assessmentId, campaignName):
    return 34
    query = json.dumps(
        {
            "query": """
            mutation ($input: CreateCampaignInput!) {
                campaign {
                    create(input: $input) {
                        campaigns {
                            id
                            name
                            description
                        }
                    }
                }
            }
        """,
            "variables": {
                "input": {
                    "db": f"{index}",
                    "assessmentId": f"{assessmentId}",
                    "campaignData": [
                        {
                            "name": f"{campaignName}",
                            "description": f"Created by {getpass.getuser()}",
                        }
                    ],
                }
            },
        }
    )

    response = send_request(vectr_url, vectr_headers, query)
    if "Assessment already exists" in str(response) and "ValidationError" in str(
        response
    ):
        campaigns_in_vectr = get_campaigns(vectr_url, vectr_headers, index)
        campaignId = do_assessment(campaigns_in_vectr, campaign)
    else:
        campaignId = response["data"]["campaign"]["create"]["campaigns"][0]["id"]

    return campaignId


def create_testcase_template(
    vectr_url,
    vectr_headers,
    index,
    campaignId,
    technique_name,
    technique_id,
    phase,
    orgId,
):
    query = json.dumps(
        {
            "query": """
            mutation ($input: CreateTestCaseAndTemplateMatchByNameInput!) {
                testCase {
                    createWithTemplateMatchByName(input: $input) {
                        testCases {
                            id
                            name
                            templateId
                        }
                    }
                }
            }
            """,
            "variables": {
                "input": {
                    "db": f"{index}",
                    "campaignId": f"{campaignId}",
                    "createTestCasedata": [
                        {
                            "templateName": f"{technique_name} Template",
                            "testCaseData": {
                                "name": f"{technique_name} Test Case",
                                "description": f"This is a {technique_name} simulation test case.",
                                "phase": f"{phase}",
                                "technique": f"{technique_id}",
                                "organization": f"{orgId}",
                            },
                        }
                    ],
                }
            },
        }
    )
    send_request(vectr_url, vectr_headers, query)

    return f"{technique_name} Template"


def send_to_vectr(
    vectr_url,
    vectr_headers,
    index,
    campaignId,
    activity_desc,
    technique_name,
    technique_id,
    opGuidance,
    detectionGuidance,
    redToolsName,
    phase,
    orgName,
    orgId,
):
    # check if template exists with the provided name
    template_exists = get_testcase_templates(vectr_url, vectr_headers)
    if template_exists == "N":
        create_testcase_template(
            vectr_url,
            vectr_headers,
            index,
            campaignId,
            technique_name,
            technique_id,
            phase,
            orgId,
        )
    query = json.dumps(
        {
            "query": """
    mutation CreateTestCases($input: CreateTestCaseAndTemplateMatchByNameInput!) {
      testCase {
        createWithTemplateMatchByName(input: $input) {
          testCases {
            id
            name
            templateId
          }
        }
      }
    }
    """,
            "variables": {
                "input": {
                    "db": f"{index}",
                    "campaignId": f"{campaignId}",
                    "createTestCasedata": [
                        {
                            "templateName": f"{technique_name} Template",
                            "testCaseData": {
                                "name": f"{technique_name}",
                                "description": f"{activity_desc}",
                                "phase": f"{phase}",
                                "technique": f"{technique_id}",
                                "organization": f"{orgName}",
                                "operatorGuidance": f"{opGuidance}",
                                "detectionSteps": detectionGuidance,
                                "redTools": redToolsName,
                            },
                        }
                    ],
                }
            },
        }
    )

    return query
    response = send_request(vectr_url, vectr_headers, query)


def build_payload(data):
    index = data["index"]
    technique_id = data["technique_id"]
    technique_name = data["technique"]
    phase = do_phase(phases_in_vectr, data["tactic"])
    activity_desc = data["activity_desc"]

    # obtain orgId
    org = data["org_name"]
    organization = do_org(orgs_in_vectr, org)
    orgId = json.loads(organization.replace("'", '"'))[0]["id"]
    orgName = json.loads(organization.replace("'", '"'))[0]["id"]

    # obtain assessmentId
    assessmentName = data["group_name"]
    assessmentHypothesis = data["hypothesis"]
    assessmentId = create_assessment(
        vectr_url, vectr_headers, index, assessmentName, assessmentHypothesis, orgId
    )

    # obtain campaignId
    campaignName = data["tactic"]
    campaignId = create_campaign(
        vectr_url,
        vectr_headers,
        index,
        assessmentId,
        campaignName,
    )

    # build test case payload
    opGuidance = str(data["op_guidance"])
    detectionGuidance = data["detect_guidance"]
    redtools = data["red_tool"]
    if len(redtools) > 0:
        redTools = do_redtools(redtools_in_vectr, redtools)
    else:
        redTools = do_redtools(redtools_in_vectr, "")
    if len(detectionGuidance) > 0:
        detectionGuidance = do_detectionGuidance(detectionGuidance)

    payload = send_to_vectr(
        vectr_url,
        vectr_headers,
        index,
        campaignId,
        activity_desc,
        technique_name,
        technique_id,
        opGuidance,
        detectionGuidance,
        redTools,
        phase,
        orgName,
        orgId,
    )

    return payload
