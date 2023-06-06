#This file is part of ElectricEye.
#SPDX-License-Identifier: Apache-2.0

#Licensed to the Apache Software Foundation (ASF) under one
#or more contributor license agreements.  See the NOTICE file
#distributed with this work for additional information
#regarding copyright ownership.  The ASF licenses this file
#to you under the Apache License, Version 2.0 (the
#"License"); you may not use this file except in compliance
#with the License.  You may obtain a copy of the License at

#http://www.apache.org/licenses/LICENSE-2.0

#Unless required by applicable law or agreed to in writing,
#software distributed under the License is distributed on an
#"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#KIND, either express or implied.  See the License for the
#specific language governing permissions and limitations
#under the License.

from processor.outputs.output_base import ElectricEyeOutput
import json
import pandas as pd
import matplotlib.pyplot as plt
from os import path
from datetime import datetime

here = path.abspath(path.dirname(__file__))

# NOTE: This must be updated as Frameworks are added and should match the titles given to them
SUPPORTED_FRAMEWORKS = [
    "NIST CSF V1.1",
    "NIST SP 800-53 Rev. 4",
    "AICPA TSC",
    "ISO 27001:2013",
    "CIS Critical Security Controls V8",
    "NIST SP 800-53 Rev. 5",
    "NIST SP 800-171 Rev. 2",
    "CSA Cloud Controls Matrix V4.0",
    "CMMC 2.0",
    "UK NCSC Cyber Essentials V2.2",
    "HIPAA Security Rule 45 CFR Part 164 Subpart C",
    "FFIEC Cybersecurity Assessment Tool",
    "NERC Critical Infrastructure Protection",
    "NYDFS 23 NYCRR Part 500",
    "UK NCSC Cyber Assessment Framework V3.1",
    "PCI-DSS V4.0",
    "NZISM V3.5",
    "ISO 27001:2022",
    "Critical Risk Profile V1.2",
    "ECB CROE",
    "Equifax SCF V1.0"
]

with open(f"{here}/mapped_compliance_controls.json") as jsonfile:
    CONTROLS_CROSSWALK = json.load(jsonfile)

@ElectricEyeOutput
class JsonProvider(object):
    __provider__ = "html_compliance"

    def write_findings(self, findings: list, output_file: str, **kwargs):
        if len(findings) == 0:
            print("There are not any findings to write to file!")
            exit(0)

        # Process the findings
        processedFindings = self.process_findings(findings)
        # Delete the un-processed findings
        del findings

        uniqueControls = self.get_unique_controls(processedFindings)
        # Gather and sort the control data enriched with aggregated asset information
        assetInfoAggregation = self.get_asset_information_per_control(processedFindings)
        assetDataPerControl = []
        for control, details in assetInfoAggregation.items():
            controlAssetPayload = {"ControlId": control}
            controlAssetPayload.update(details)
            assetDataPerControl.append(controlAssetPayload)

        # Do one more pass on the aggregated information and add a passing % per control
        assetDataPerControlWithPercentage = []
        for controlData in assetDataPerControl:
            passingPercentage = (controlData["PassingControls"] / controlData["ResourcesImpacted"]) * 100
            roundedPercentage = f"{round(passingPercentage, 2)}%"
            controlData["RawPassingScore"] = passingPercentage
            controlData["PassingPercentage"] = roundedPercentage
            assetDataPerControlWithPercentage.append(controlData)

        del assetDataPerControl
        # Get the aggregated pass/fail info per control
        controlsAggregation = self.generate_controls_aggregation(uniqueControls, processedFindings)

        self.html_creation(processedFindings, controlsAggregation, assetDataPerControlWithPercentage, output_file)

        print("Created HTML Compliance report!")

    def process_findings(self, findings):
        """
        Returns a processed list of findings
        """

        processedFindings = []

        for finding in findings:
            complianceRelatedRequirements = finding["Compliance"]["RelatedRequirements"]
            nistCsfControls = [control for control in complianceRelatedRequirements if control.startswith("NIST CSF V1.1")]
            for control in nistCsfControls:
                crosswalkedControls = self.nist_csf_v_1_1_controls_crosswalk(control)
                # Not every single NIST CSF Control maps across to other frameworks
                if crosswalkedControls is not None:
                    complianceRelatedRequirements.extend(crosswalkedControls)
                else:
                    continue
            
            processedFindings.append(
                {
                    "AssetId": finding["Resources"][0]["Id"],
                    "ProviderAccountId": finding["ProductFields"]["ProviderAccountId"],
                    "Provider": finding["ProductFields"]["Provider"],
                    "AssetRegion": finding["ProductFields"]["AssetRegion"],
                    "AssetClass": finding["ProductFields"]["AssetClass"],
                    "AssetService": finding["ProductFields"]["AssetService"],
                    "AssetComponent": finding["ProductFields"]["AssetComponent"],
                    "ComplianceStatus": finding["Compliance"]["Status"],
                    "ComplianceRelatedRequirements": complianceRelatedRequirements,
                }
            )

        print(f"Processed {len(processedFindings)} findings")

        return processedFindings
    
    def nist_csf_v_1_1_controls_crosswalk(self, nistCsfSubcategory):
        """
        This function returns a list of additional control framework control IDs that mapped into a provided
        NIST CSF V1.1 Subcategory (control)
        """

        # Not every single NIST CSF Control maps across to other frameworks
        try:
            return CONTROLS_CROSSWALK[nistCsfSubcategory]
        except KeyError:
            return None

    def get_unique_controls(self, processedFindings):
        """
        This function returns a list of unique controls across all processed findings
        """

        uniqueControls = []

        for findings in processedFindings:
            for controls in findings["ComplianceRelatedRequirements"]:

                if controls not in uniqueControls:
                    uniqueControls.append(controls)
                else:
                    continue

        print(f"{len(uniqueControls)} unique controls processed")

        return uniqueControls

    def get_asset_information_per_control(self, processedFindings):
        """
        This function returns a DataFrame of controls with the sum of each Account, Asset, and Region in scope for a control
        """

        controlDict = {}

        for asset in processedFindings:
            for control in asset["ComplianceRelatedRequirements"]:
                if control == "NIST SP 800-53 Rev. 4 AC-1NIST SP 800-53 Rev. 4 AC-3NIST SP 800-53 Rev. 4 AC-17NIST SP 800-53 Rev. 4 AC-22ISO 27001:2013 A.13.1.2":
                    continue

                if control not in controlDict:
                    controlDict[control] = {
                        "UniqueAssetClass": set(),
                        "UniqueAssetComponent": set(), 
                        "UniqueAssetService": set(),
                        "ResourcesImpacted": set(),
                        "PassingControls": set(),
                        "FailingControls": set(),
                    }
                controlDict[control]["UniqueAssetClass"].add(asset["AssetClass"])
                controlDict[control]["UniqueAssetComponent"].add(asset["AssetComponent"])
                controlDict[control]["UniqueAssetService"].add(asset["AssetService"])
                controlDict[control]["ResourcesImpacted"].add(asset["AssetId"])
                if asset["ComplianceStatus"] == "PASSED":
                    controlDict[control]["PassingControls"].add(asset["AssetId"])
                else:
                    controlDict[control]["FailingControls"].add(asset["AssetId"])

        # Now transform the sets into counts
        for control, details in controlDict.items():
            for key, unique_set in details.items():
                controlDict[control][key] = len(unique_set)

        print("Completed aggregation of Asset details per Control for all frameworks.")
            
        return controlDict

    def generate_controls_aggregation(self, uniqueControls, processedFindings):
        """
        This function returns a complex dictionary that records the statistics of all audit readiness frameworks by passing and failing checks
        """

        # Create a dict of nested dicts from a list comprehension of a list of Supported Frameworks...holy shit what a word salad
        controlsStatusAggregation = {framework: {} for framework in SUPPORTED_FRAMEWORKS}
        # Populate the data structure of pass/fail by individual controls
        for controlTitle in uniqueControls:
            for framework in SUPPORTED_FRAMEWORKS:
                if controlTitle.startswith(framework):
                    controlsStatusAggregation[framework][controlTitle] = {"Passed": 0, "Failed": 0}

        del uniqueControls

        # Now start to count up the pass & fails
        for finding in processedFindings:
            status = finding["ComplianceStatus"]
            for controls in finding["ComplianceRelatedRequirements"]:
                for framework in SUPPORTED_FRAMEWORKS:
                    if controls.startswith(framework):
                        if status == "PASSED":
                            controlsStatusAggregation[framework][controls]["Passed"] += 1
                        else:
                            controlsStatusAggregation[framework][controls]["Failed"] += 1

        print("Finished aggregating Pass/Fail stats for all controls.")

        return controlsStatusAggregation

    def generate_control_table(self, framework, controls, aggregatedAssetControlsData):
        """
        This function returns a JSON object that contains the Control ID and information about the control from the framework/standard author
        joined with the information from "get_asset_information_per_control" which is used for the HTML table in the report
        """

        tableContent = []

        print(f"Generating a table of controls objectives and aggregated asset information for {len(controls)} controls in {framework}")
        
        with open(f"{here}/control_objectives.json") as jsonfile:
            data = json.load(jsonfile)

        for controlInfo in data:
            controlTitle = controlInfo["ControlTitle"]
            # Only grab controls that match the framework that are in the covered controls
            if controlTitle.startswith(framework) and controlTitle in controls:
                contentRow = {
                    "ControlTitle": controlTitle,
                    "ControlDescription": controlInfo["ControlDescription"]
                }
                tableContent.append(contentRow)
            else:
                continue

        if tableContent:
            tableDf = pd.DataFrame(tableContent)
            aggAssetControlsDf = pd.DataFrame(aggregatedAssetControlsData)

            tableContentDf = tableDf.merge(
                aggAssetControlsDf,
                how="left",
                left_on="ControlTitle",
                right_on="ControlId"
            )

            del tableContentDf["ControlId"]

            tableContent = json.loads(tableContentDf.to_json(index=False,orient="table"))

            del tableContentDf

            print(f"Finished generating the table for {framework}")

            return tableContent["data"]
        else:
            return []

    def generate_executive_summary(self, processedFindings):
        """
        Returns a paragraph for the summary header section of the report
        """

        countUniqueControls = len(self.get_unique_controls(processedFindings))
        countFindings = len(processedFindings)

        providerAssesed = processedFindings[0]["Provider"]

        # Compliance Passed v Failed
        totalPassed = [finding for finding in processedFindings if finding["ComplianceStatus"] == "PASSED"]

        passingPercentage = (len(totalPassed) / countFindings) * 100
        roundedPercentage = f"{round(passingPercentage, 2)}%"

        regionsAssessed = []
        accountsAssessed = []
        assetClassesAssesed = []
        assetServicesAssessed = []
        assetComponentsAssessed = []
        uniqueResourcesIds = []

        # Append uniques into lists
        for finding in processedFindings:
            if finding["AssetRegion"] not in regionsAssessed:
                regionsAssessed.append(finding["AssetRegion"])

            if finding["ProviderAccountId"] not in accountsAssessed:
                accountsAssessed.append(finding["ProviderAccountId"])

            if finding["AssetClass"] not in assetClassesAssesed:
                assetClassesAssesed.append(finding["AssetClass"])

            if finding["AssetService"] not in assetServicesAssessed:
                assetServicesAssessed.append(finding["AssetService"])

            if finding["AssetComponent"] not in assetComponentsAssessed:
                assetComponentsAssessed.append(finding["AssetComponent"])

            if finding["AssetId"] not in uniqueResourcesIds:
                uniqueResourcesIds.append(finding["AssetId"])

        # Use len to get counts
        countRegionsAssessed = len(regionsAssessed)
        countAccountsAssessed = len(accountsAssessed)
        countAssetClassesAssesed = len(assetClassesAssesed)
        countAssetServicesAssessed = len(assetServicesAssessed)
        countAssetComponentsAssessed = len(assetComponentsAssessed)
        countUniqueResourceIds = len(uniqueResourcesIds)

        # Use join to create sentences of certain lists
        regionSentence = ", ".join(regionsAssessed)
        accountSentence = ", ".join(accountsAssessed)
        assetClassSentence = ", ".join(assetClassesAssesed)
        assetServiceSentence = ", ".join(assetServicesAssessed)
        assetComponentSentence = ", ".join(assetComponentsAssessed)

        summary = f"""
            ElectricEye is a multi-cloud, multi-SaaS Python CLI tool for Asset Management, Security Posture Management & Attack Surface Monitoring supporting 100s of services and evaluations to harden your public cloud & SaaS environments with controls mapped to NIST CSF, 800-53, ISO 27001, AICPA TSC (SOC2), and more! Each Check within ElectricEye evaluates a specific component for a specific service for a specific Cloud Service Provider or SasS Vendor such as Amazon EC2 Instance, Oracle Cloud Autonomous Date Warehouses, Google Cloud SQL instances, M365 Conditional Access Policies, ServiceNow Secure Access Configurations, and more. For each of those checks, several controls mapping to NIST CSF are provided which are in turn mapped to other major frameworks which can aid in audit readiness or other internal audit or controls management exercises. This report is not an attestation, certificate, or fancy plaque you paid for that says "SOC2" on it.</br>


            </br>During the evaluation for {providerAssesed}, ElectricEye generated {countFindings} findings with a passing rate for every single finding is {roundedPercentage} for {countUniqueResourceIds} unique Assets across {countAccountsAssessed} Cloud/SaaS Accounts ({accountSentence}) in {countRegionsAssessed} cloud Regions/Zones/Datacenter locations ({regionSentence}).</br>
            
            </br>Across all of these findings generated by ElectricEye, {countUniqueControls} controls were assessed across all frameworks which covered {countAssetClassesAssesed} distinct Asset Classes comprising of {countAssetServicesAssessed} distinct Asset Services which in turn are comprising of {countAssetComponentsAssessed} Asset Components</br>

            </br> Asset Classes: </br>
            <ul>{assetClassSentence}</ul>
            </br> Asset Services: </br>
            <ul>{assetServiceSentence}</ul>
            </br> Asset Components: </br>
            <ul>{assetComponentSentence}</ul>

            </br>This report provides a per-Control breakdown for each Framework that ElectricEye supports, showing you both how many Findings were passed or failed as well as the total passing score per Framework. Below each set of graphics, a table is provided which includes the specific Control identifiers that were checked for the current evaluation, the control description or control objectives (provided by the owners/authors of the standard or framework itself), as well as aggregated Asset information which includes how many unique Classes, Services, and Components were covered per Control as well as the overall Findings per Control.</br>

            </br>This report can be used as a point-in-time snapshot for control sampling or as a guideline before the start of an engagement for audit readiness, cloud hygeine, or other internal audit or GRC related projects. For better and more controlled sampling and time-series analysis, it is recommended to use another output such as JSON or CSV and storing those data snapshots within a data lake or data warehouse for better aggregation and querying.</br>
        """

        print("Generating Summary report.")

        return summary

    def create_visuals(self, controlsAggregation, assetDataPerControl):
        # Loop through every high level framework aggregation to generate findings
        for framework, controls in controlsAggregation.items():
            if not controls:  # this checks if `controls` is not empty
                print(f"There are not any results for {framework}, skipping it!")
                continue
            # Continue with populated Frameworks, this is more or less to be "fuck up proof" in case I forgot to add a Framework to SUPPORTED_FRAMEWORKS
            print(f"Creating a visualization for the {framework} framework!")
            # remove shit we don't need so the filename doesn't get dicked up
            frameworkSavefile = str(framework).replace(".","").replace(" ", "").lower()
            # access the dict with the specific aggregations
            controlsData = controlsAggregation[framework]

            # Loop the newly assembled list, only taking the controls for a specific framework that comes from the CONSTANT of all available frameworks 
            # at a time and use the info to assemble into a dataframe to combine with another dataframe based on controls information
            if framework in SUPPORTED_FRAMEWORKS:
                aggregatedAssetControlsData = [info for info in assetDataPerControl if info["ControlId"].startswith(framework)]
            else:
                aggregatedAssetControlsData = []

            # Parse out the specific unique controls (again) to get the right information on the controls for the HTML table
            controls = [control for control in controlsData]
            tableContent = self.generate_control_table(framework, controls, aggregatedAssetControlsData)
            # Sort the table to match the descending values of the matplot lib charts
            tableContent = sorted(tableContent, key=lambda x: x["ResourcesImpacted"], reverse=False)

            # Reverse order sorting of the controls, that will put the controls with the most failures closer to the X-Axis
            controlsData = dict(sorted(controlsData.items(), key=lambda item: item[1]["Passed"] + item[1]["Failed"], reverse=True))

            # create a figure with two subplots: one for the bar chart and one for the donut chart
            fig, axs = plt.subplots(nrows=2, figsize=(38, 22), tight_layout=True)
            """# Set the text size within the elements
            plt.rcParams['font.size'] = 16  # Change the default font size
            plt.rcParams['axes.labelsize'] = 14  # Increase the size of axis labels
            plt.rcParams['axes.titlesize'] = 16  # Increase the size of the figure title
            plt.rcParams['xtick.labelsize'] = 16  # Increase the size of x-tick labels
            plt.rcParams['ytick.labelsize'] = 16  # Increase the size of y-tick labels"""

            # sum of all passed and failed to calculate percentages later
            controlsPassedSum = controlsFailedSum = 0

            # iterate over the dictionary to plot each bar chart
            for i, (key, value) in enumerate(controlsData.items()):
                passed = value["Passed"]
                failed = value["Failed"]

                controlsPassedSum += passed
                controlsFailedSum += failed
                # Create horizontal bar chart, add a label to the X-Axis, and finally add values for the bars
                #Set a title, axs[0].set_title(f"ElectricEye {frameworkTitle} Audit Readiness Report - {timeNow}", fontsize=14, fontweight="bold")
                axs[0].barh(key, passed, color="#6aaf35")
                axs[0].barh(key, failed, left=passed, color="#fe6e73")
                axs[0].set_xlabel("Total Checks In Scope", fontsize=16)
                axs[0].text(passed, i, str(passed), color="black", va="center")  # label for "Passed"
                axs[0].text(passed + failed, i, str(failed), color="red", va="center")  # label for "Failed"

            # create a legend for the bar chart
            passed_patch = plt.Rectangle((0,0),1,1,fc="#6aaf35", edgecolor = "none")
            failed_patch = plt.Rectangle((0,0),1,1,fc="#fe6e73",  edgecolor = "none")
            axs[0].legend([passed_patch, failed_patch], ["Passed", "Failed"], loc="upper right")

            # create a donut chart with the overall passing and failing percentages
            sizes = [controlsPassedSum, controlsFailedSum]
            colors = ["#6aaf35", "#fe6e73"]

            axs[1].pie(sizes, labels=["Passed", "Failed"], colors=colors, autopct="%1.1f%%", startangle=90)
            # this creates the hole in the middle, effectively making the pie chart a donut chart
            axs[1].add_artist(plt.Circle((0,0),0.70,fc="white"))  

            # Set the facecolor of the figure and the plots to a very light gray
            plt.rcParams["savefig.facecolor"]="f9f9f9"
            plt.rcParams["axes.facecolor"]="f9f9f9"

            # Save the charts as a SVG and then read out the contents to pass to HTML
            fig.savefig(f"{here}/{frameworkSavefile}.svg", format="svg")
            with open(f"{here}/{frameworkSavefile}.svg", "r") as f:
                svgImageContents = f.read()

            yield tableContent, svgImageContents, framework

    def generate_stylesheet(self):
        """
        This function generates a stylesheet for the compliance report
        """
        stylesheet = '''
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: Arial,sans-serif;
            font-size: 16px;
        }

        body {
            display: flex;
            background-attachment: fixed;
            background-size: 100%;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }

        .summary__header {
            box-shadow: 0 .4rem .8rem #0005;
            margin-top: 20px;
            border-radius: .5rem;
            width: auto;
            height: auto;
            max-width: 97%;
            background-color: #ecebed;
            padding: .8rem 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .summary__header__image {
            max-width: 120px;
            max-height: 120px;
            align-items: center;
        }

        figure {
            margin-left: 0.5%;
            margin-right: 1%;
        }

        figcaption {
            font-size: 18px;
            font-weight: bold;
            justify-content: center;
            text-align: center;
        }

        table {
            width: 100%;
        }

        table, th, td {
            border-collapse: collapse;
            padding: 1rem;
            text-align: left;
        }

        thead th {
            position: sticky;
            top: 0;
            left: 0;
            cursor: pointer;
            text-transform: capitalize;
            font-weight: bold;
            text-align: left;
            background-color: #7ec0e0;
        }

        thead tr {
            border-bottom: 2px solid #dddddd;
        }

        tbody tr:nth-child(even) {
            background-color: #0000000b;
        }

        svg {
            width: auto;
            height: auto;
            max-width: 100%;
            overflow: hidden;
        }

        .chart__image {
            border-radius: .2rem;
            margin-top: 25px;
            margin-bottom: 25px;
        }

        .table__body {
            width: 98%;
            max-height: 98%;
            background-color: #fffb;
            margin: .8rem auto;
            border-radius: .6rem;
            box-shadow: 0 .4rem .8rem #0005;
            overflow: auto;
            overflow: overlay;
        }

        .table__body::-webkit-scrollbar{
            width: 0.5rem;
            height: 0.5rem;
        }

        .table__body::-webkit-scrollbar-thumb{
            border-radius: .5rem;
            background-color: #0004;
            visibility: hidden;
        }

        .table__body:hover::-webkit-scrollbar-thumb{ 
            visibility: visible;
        }

        .framework__header {
            margin-top: 20px;
            margin-bottom: 20px;
            border-radius: .5rem;
            padding: .8rem 1rem;
            
            width: auto;
            height: auto;
            max-height: 90%;
            max-width: 97%;

            display: flex;
            justify-content: space-between;
            align-items: center;

            background-color: #ecebed;
            box-shadow: 0 .4rem .8rem #0005;
        }

        .framework__header__image {
            align-items: center;
        }

        p {
            font-weight: bold;
        }

        .score {
            padding: .4rem 0;
            border-radius: 2.5rem;
            text-align: center;
            max-width: 95%;
        }

        .score.reallybad {
            background-color: rgb(214, 63, 56);
            color: #ffc400;
        }

        .score.bad {
            background-color: rgb(254, 110, 115);
            color: #fff;
        }

        .score.meh {
            background-color: rgb(248, 146, 86);
        }

        .score.good {
            background-color: #d1db00;
        }

        .score.great {
            background-color: #6aaf35;
            color: white;
        }

        footer {
            height: 1.5rem; /* Footer height */
            text-align: center;
            color: black;
        }
        '''

        return stylesheet

    def framework_section_information_generator(self, framework):
        """
        This function returns an <img> / <svg> tag along with some background information about frameworks to use as a spacer between the charts and tables
        """
        # NIST CSF V1.1
        if framework == "NIST CSF V1.1":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/nist_csf_v11.jpg" class="framework__header__image">'
            frameworkInfo = "The NIST Cybersecurity Framework is voluntary guidance, based on existing standards, guidelines, and practices to help organizations better manage and reduce cybersecurity risk. It fosters cybersecurity risk  management and related communications among both internal and external stakeholders, and for larger organizations, helps to better integrate and align cybersecurity risk management with broader enterprise risk management processes as described in the NISTIR 8286 series.The Framework is organized by five key Functions: Identify, Protect, Detect, Respond, Recover. These five widely understood terms, when considered together, provide a comprehensive view of the lifecycle for managing cybersecurity over time."
        
        # 800-53 R4
        elif framework == "NIST SP 800-53 Rev. 4":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/nist_80053_rev4.jpg" class="framework__header__image">'
            frameworkInfo = "This publication provides a catalog of security and privacy controls for federal information systems and organizations and a process for selecting controls to protect organizational operations (including mission, functions, image, and reputation), organizational assets, individuals, other organizations, and the Nation from a diverse set of threats including hostile cyber attacks, natural disasters, structural failures, and human errors (both intentional and unintentional). The security and privacy controls are customizable and implemented as part of an organization-wide process that manages information security and privacy risk. The controls address a diverse set of security and privacy requirements across the federal government and critical infrastructure, derived from legislation, Executive Orders, policies, directives, regulations, standards, and/or mission/business needs. The publication also describes how to develop specialized sets of controls, or overlays, tailored for specific types of missions/business functions, technologies, or environments of operation. Finally, the catalog of security controls addresses security from both a functionality perspective (the strength of security functions and mechanisms provided) and an assurance perspective (the measures of confidence in the implemented security capability). Addressing both security functionality and assurance helps to ensure that information technology component products and the information systems built from those products using sound system and security engineering principles are sufficiently trustworthy."
        
        # AICPA TSC/SOC
        elif framework == "AICPA TSC":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/aicpa_soc.jpg" class="framework__header__image">'
            frameworkInfo = f"""
                The 2017 Trust Services Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy presents control criteria established by the Assurance Services Executive Committee (ASEC) of the AICPA for use in attestation or consulting engagements to evaluate and report on controls over the security, availability, processing integrity, confidentiality, or privacy of information and systems (a) across an entire entity; (b) at a subsidiary, division, or operating unit level; (c) within a function relevant to the entity's operational, reporting, or compliance objectives; or (d) for a particular type of information used by the entity. The trust services criteria were designed to provide flexibility in application and use for a variety of different subject matters. The following are the types of subject matters a practitioner may be engaged to report on using the trust services criteria:</br>
                
                </br>The effectiveness of controls within an entity's cybersecurity risk management program to achieve the entity's cybersecurity objectives using the trust services criteria relevant to security, availability, and confidentiality as control criteria in a SOC for Cybersecurity examination.</br>

                </br>The suitability of design and operating effectiveness of controls included in management's description of a service organization's system relevant to one or more of the trust services criteria over security, availability, processing integrity, confidentiality, or privacy throughout a specified period to achieve the entity's objectives based on those criteria in a type 2 SOC 2 engagement. A type 2 SOC 2 engagement, which includes an opinion on the operating effectiveness of controls, also includes a detailed description of tests of controls performed by the service auditor and the results of those tests. A type 1 SOC 2 engagement addresses the same subject matter as a type 2 SOC 2 engagement; however, a type 1 SOC 2 report does not contain an opinion on the operating effectiveness of controls nor a detailed description of tests of controls performed by the service auditor and the results of those tests.</br>

                </br>The design and operating effectiveness of a service organization's controls over a system relevant to one or more of the trust services criteria over security, availability, processing integrity, confidentiality, and privacy in a SOC 3 engagement. A SOC 3 report contains an opinion on the operating effectiveness of controls but does not include a detailed description of tests of controls performed by the service auditor and the results of those tests.</br>
            """
        
        # ISO 27001:2013/2017
        elif framework == "ISO 27001:2013":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/iso_27k1_2013.jpg" class="framework__header__image">'
            frameworkInfo = "ISO 27001 is an international standard that provides a framework for establishing, implementing, maintaining, and continually improving an information security management system (ISMS). The standard defines a set of requirements and controls to help organizations manage and protect their information assets. Annex A of ISO 27001 contains a comprehensive list of controls that organizations can choose to implement based on their specific needs and risk assessment. These controls are categorized into 14 sections, covering various aspects of information security. Organizations use the Annex A controls as a reference to identify the specific measures they need to implement to protect their information assets. These controls are based on best practices and provide a systematic approach to managing information security risks. By implementing these controls, organizations can establish a robust information security management system, reduce the likelihood and impact of security incidents, meet regulatory requirements, and build trust with customers and stakeholders. The ISO 27001 standard and Annex A controls are widely recognized and adopted globally as a means to ensure the confidentiality, integrity, and availability of information assets and to demonstrate a commitment to information security management."
        
        # CIS Critical Security Controls V8
        elif framework == "CIS Critical Security Controls V8":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/cis_critical_controls_v8.jpg" class="framework__header__image">'
            frameworkInfo = """
            CIS Critical Security Controls Version 8 are a prioritized set of Safeguards to mitigate the most prevalent cyber-attacks against systems and networks. They are mapped to and referenced by multiple legal, regulatory, and policy frameworks. CIS Controls v8 has been enhanced to keep up with modern systems and software. Movement to cloud-based computing, virtualization, mobility, outsourcing, Work-from-Home, and changing attacker tactics prompted the update and supports an enterprise's security as they move to both fully cloud and hybrid environments. The CIS Controls were developed starting in 2008 by an international, grass-roots consortium bringing together companies, government agencies, institutions, and individuals from every part of the ecosystem (cyber analysts, vulnerability-finders, solution providers, users, consultants, policy-makers, executives, academia, auditors, etc.) who banded together to create, adopt, and support the CIS Controls. The expert volunteers who develop the Controls apply their first-hand experience to develop the most effective actions for cyber defense. Prioritization is a key benefit to the CIS Controls. They were designed to help organizations rapidly define the starting point for their defenses, direct their scarce resources on actions with immediate and high-value payoff, and then focus their attention and resources on additional risk issues that are unique to their business or mission.</br>

            </br>The CIS Controls are not a replacement for any existing regulatory, compliance, or authorization scheme. The CIS Controls map to most major compliance frameworks such as the NIST Cybersecurity Framework, NIST 800-53, ISO 27000 series and regulations such as PCI DSS, HIPAA, NERC CIP, and FISMA. Mappings from the CIS Controls have been defined for these other frameworks to give a starting point for action. Additionally, the CIS Controls do not have a formalized certification, examination or attestation process for them. ElectricEye maps backwards to Critical Controls from the NIST CSF V1.1 subcategories that every single ElectricEye Check is mapped against.
            """

        # 800-53 R5
        elif framework == "NIST SP 800-53 Rev. 5":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/nist_80053_rev5.jpg" class="framework__header__image">'
            frameworkInfo = """
            NIST Special Publication 800-53 (Revision 5) provides a catalog of security and privacy controls for information systems and organizations to protect organizational operations and assets, individuals, other organizations, and the Nation from a diverse set of threats and risks, including hostile attacks, human errors, natural disasters, structural failures, foreign intelligence entities, and privacy risks. The controls are flexible and customizable and implemented as part of an organization-wide process to manage risk. The controls address diverse requirements derived from mission and business needs, laws, executive orders, directives, regulations, policies, standards, and guidelines. Finally, the consolidated control catalog addresses security and privacy from a functionality perspective (i.e., the strength of functions and mechanisms provided by the controls) and from an assurance perspective (i.e., the measure of confidence in the security or privacy capability provided by the controls). Addressing functionality and assurance helps to ensure that information technology products and the systems that rely on those products are sufficiently trustworthy.</br>
            
            </br>SP 800-53 Rev. 5 provides industry-agnostic security controls that are widely applicable beyond those who are part of the United States Defense Industrial Base (DIB) or other Allies and critical infrastructure providers. ElectricEye does recommend using NIST 800-53 Rev. 5 as your controls framework where you do not have one. While many frameworks draw their mapping from NIST SP 800-53, there is not a formalized certification, examination or attestation process for them. ElectricEye does not cover every single control, and only covers the mapping of NIST SP 800-53 Rev. 5 controls to CIS Critical Controls V8 which is mapped to the NIST CSF V1.1 subcategories that all ElectricEye Checks are mapped against. ElectricEye will not contextualize any compensating controls or exceptions that you define.
            """
        
        # 800-171 R2
        elif framework == "NIST SP 800-171 Rev. 2":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/nist_800171_rev2.jpg" class="framework__header__image">'
            frameworkInfo = """
            The protection of Controlled Unclassified Information (CUI) resident in nonfederal systems and organizations is of paramount importance to federal agencies and can directly impact the ability of the federal government to successfully conduct its essential missions and functions. NIST Special Publication 800-171 (Revision 2) provides agencies with recommended security requirements for protecting the confidentiality of CUI when the information is resident in nonfederal systems and organizations; when the nonfederal organization is not collecting or maintaining information on behalf of a federal agency or using or operating a system on behalf of an agency; and where there are no specific safeguarding requirements for protecting the confidentiality of CUI prescribed by the authorizing law, regulation, or governmentwide policy for the CUI category listed in the CUI Registry. The requirements apply to all components of nonfederal systems and organizations that process, store, and/or transmit CUI, or that provide protection for such components. The security requirements are intended for use by federal agencies in contractual vehicles or other agreements established between those agencies and nonfederal organizations.</br>
            
            </br>SP 800-171 is a subset of 800-53 controls that are meant to apply only to organizations that handle CUI, ElectricEye does not recommend building a program solely around these controls as they are not as other industry-agnostic controls frameworks such as NIST SP 800-53, Cloud Security Alliance's Cloud Controls Matrix or the Cyber Risk Institute's Critical Risk Profile. ElectricEye does not cover every single control, and only covers the mapping of NIST SP 800-171 Rev. 2 controls to CIS Critical Controls V8 which is mapped to the NIST CSF V1.1 subcategories that all ElectricEye Checks are mapped against. ElectricEye will not contextualize any compensating controls or exceptions that you define.
            """

        # CSA Cloud Controls Matrix V4.0
        elif framework == "CSA Cloud Controls Matrix V4.0":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/csa_ccm_v4.jpg" class="framework__header__image">'
            frameworkInfo = """
            The Cloud Security Alliance (CSA) Cloud Controls Matrix (CCM) is a framework that provides security controls and best practices for organizations to assess and evaluate the security of cloud service providers (CSPs). The CCM aims to help organizations make informed decisions about the security of their data and systems when adopting cloud services. The CCM covers a broad range of security domains, including governance and risk management, compliance and audit, data security and privacy, human resources, operations management, and incident response. Each domain includes a set of security controls and best practices that organizations can use to evaluate CSPs. The CCM defines control objectives for each security domain, which provide specific outcomes that organizations should strive to achieve. These objectives help guide organizations in assessing the effectiveness and maturity of a CSP's security controls. The security controls within the CCM are organized into control families. Each control family focuses on a specific aspect of security, such as access control, data encryption, vulnerability management, or business continuity. These control families help structure the assessment and evaluation of a CSP's security practices.</br>
            
            </br>The CSA Cloud Controls Matrix (CCM), the Consensus Assessments Initiative Questionnaire (CAIQ), and the CSA Security, Trust, and Assurance Registry (STAR) are all interconnected components of the Cloud Security Alliance's (CSA) framework for evaluating and assessing the security of cloud service providers (CSPs). The CAIQ is a standardized questionnaire that aligns with the CCM. It consists of a series of Yes/No questions based on the CCM's control objectives and control families. The CAIQ is designed to facilitate the assessment and evaluation of a CSP's security practices by providing a structured and consistent approach. The STAR program provides a publicly accessible registry where CSPs and other companies which are primarily hosted on the public cloud can document their security capabilities, practices, and certifications. CSPs can submit a completed CAIQ to obtain a listing in the STAR registry. The STAR registry enables organizations to access valuable information about a CSP's security posture, certifications, and compliance efforts.</br>

            </br>STAR Level I involves filling out the CAIQ and submitting it to the STAR Registry while STAR Level II requires a qualified third-party assessor to provide a higher level of assurance and validation for organizations and CSPs within the program. ElectricEye recommends using the CCM to measure the health of your cloud security program and as a controls framework if you do not have anyway, ElectricEye can help with providing information for filling out the CAIQ but ElectricEye does not cover every single control, and only covers the mapping of CCM V4.0 controls to CIS Critical Controls V8 which is mapped to the NIST CSF V1.1 subcategories that all ElectricEye Checks are mapped against. ElectricEye will not contextualize any compensating controls or exceptions that you define.
            """

        # CMMC 2.0
        elif framework == "CMMC 2.0":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/cmmc_v2.jpg" class="framework__header__image">'
            frameworkInfo = """
            The Cybersecurity Maturity Model Certification (CMMC) is a framework developed by the U.S. Department of Defense (DoD) to enhance the cybersecurity practices and resilience of organizations within the defense industrial base (DIB). The CMMC establishes a unified standard for cybersecurity across the DIB to protect sensitive information and ensure the integrity of the supply chain. CMMC 2.0 program is the next iteration of the Department's CMMC cybersecurity model. It streamlines requirements to three levels of cybersecurity and aligns the requirements at each level with well-known and widely accepted NIST cybersecurity standards.</br>

            </br>The CMMC model is designed to protect Federal Contract Information (FCI) and Controlled Unclassified Information (CUI) that is shared with contractors and subcontractors of the Department through acquisition programs. In alignment with section 4.1901 of the Federal Acquisition Regulation (FAR), FCI is defined as information, not intended for public release, that is provided by or generated for the Government under a contract to develop or deliver a product or service to the Government, but not including information provided by the Government to the public (such as that on public websites) or simple transactional information, such as that necessary to process payments. CUI is information the Government creates or possesses, or that an entity creates or possesses for or on behalf of the Government, that a law, regulation, or Government-wide policy requires or permits an agency to handle using safeguarding or dissemination controls.</br>

            </br>Building on Defense Federal Acquisition Regulations Supplement (DFARS) 252.204-7112, the Office of the Under Secretary of Defense for Acquisition and Sustainment (OUSD(A&S)) is working with DoD stakeholders, University Affiliated Research Centers (UARCs), Federally Funded Research and Development Centers (FFRDC), and industry to develop the Cybersecurity Maturity Model Certification (CMMC). CMMC assessments allow the Department to verify the implementation of clear cybersecurity standards, Once CMMC is fully implemented, certain DoD contractors that handle sensitive unclassified DoD information will be required to achieve a particular CMMC level as a condition of contract award.</br>

            </br>Unless you are operating as part of the United States Department of Defense (DOD), Other Government Agencies (OGAs) supporting the DOD Mission, or are a member of the Defense Industrial Base (DIB) or other Prime or Subcontractor, ElectricEye recommends using the frameworks that CMMC V2.0 is derived from such as NIST 800-53 Rev. 4 or Rev. 5 and NIST CSF V1.1. ElectricEye does not cover every single control, and only covers the mapping of CMMC V2.0 controls to CIS Critical Controls V8 which is mapped to the NIST CSF V1.1 subcategories that all ElectricEye Checks are mapped against. ElectricEye will not contextualize any compensating controls or exceptions that you define, and while it can help with the self-assessment process, using ElectricEye is not the same as a proper examination and certification (whenever DOD gets around to defining that).
            """

        # UK NCSC Cyber Essentials V2.2
        elif framework == "UK NCSC Cyber Essentials V2.2":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/uk_ncsc_cyber_essentials.jpg" class="framework__header__image">'
            frameworkInfo = """
            The UK NCSC (National Cyber Security Centre) Cyber Essentials is a government-backed cybersecurity certification scheme designed to help organizations in the United Kingdom improve their cybersecurity practices and demonstrate their commitment to protecting against common cyber threats. It provides a set of foundational cybersecurity controls and best practices that organizations can implement to mitigate the risk of common cyberattacks. Organizations that wish to achieve the Cyber Essentials certification can follow a straightforward process:</br>

            </br>Self-Assessment: The organization completes a self-assessment questionnaire that covers the controls and practices outlined in the Cyber Essentials scheme. The questionnaire verifies that the organization has implemented the necessary security measures.</br>

            </br>External Review (Optional): The organization may choose to have its self-assessment independently reviewed by a certification body to provide additional assurance and credibility.</br>

            </br>Certification: Once the self-assessment and, if applicable, the external review are successfully completed, the organization is awarded the Cyber Essentials certification. The certification is valid for one year. In addition to Cyber Essentials, there is also a higher-level certification called Cyber Essentials Plus. Cyber Essentials Plus involves a more rigorous assessment that includes vulnerability testing and verification of the organization's implementation of the controls.</br>

            </br>ElectricEye recommends using Cyber Essentials (V2.2) as a controls framework if you are a government entity within the United Kingdom or otherwise provide products or services to the United Kingdom government or other entities who directly or indirectly support them. ElectricEye does not cover every single control, and only covers the mapping of FFIEC CAT controls to CIS Critical Controls V8 which is mapped to the NIST CSF V1.1 subcategories that all ElectricEye Checks are mapped against. ElectricEye will not contextualize any compensating controls or exceptions that you define, and while it can help with the self-assessment process, using ElectricEye is not the same as a proper examination and certification.
            """

        # HIPAA Security Rule 45 CFR Part 164 Subpart C
        elif framework == "HIPAA Security Rule 45 CFR Part 164 Subpart C":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/hipaa_security_rule.jpg" class="framework__header__image">'
            frameworkInfo = """
            The HIPAA Security Rule requires physicians to protect patients' electronically stored, protected health information (known as “ePHI”) by using appropriate administrative, physical and technical safeguards to ensure the confidentiality, integrity and security of this information. Essentially, the Security Rule operationalizes the protections contained in the Privacy Rule by addressing the technical and nontechnical safeguards that covered entities must implement to secure ePHI. All covered entities must assess their security risks, even those entities who utilize certified electronic health record (EHR) technology. Those entities must put in place administrative, physical and technical safeguards to maintain compliance with the Security Rule and document every security compliance measure. Technical safeguards encompass the technology, as well and the policies and procedures for its use, that protect ePHI and control access to it. They are often the most difficult regulations to comprehend and implement (45 CFR 164.312).</br>

            </br>The Security Rule incorporates the concepts of scalability, flexibility and generalization. In other words, the regulations do not expect the same security precautions from small or rural providers as are demanded of large covered entities with significant resources. Security is recognized as an evolving target, and so HIPAA's security requirements are not linked to specific technologies or products. HHS has stated it is focused more on what needs to be done and less on how it should be accomplished.</br>

            </br>As HIPAA is a law and not a controls framework or standard, if you are a Covered Entity, a Business Associated, or otherwise handle ePHI you must abide by the requirements defined within the law, full stop. HIPAA is under the purview and enforcement of the United States Health and Human Services (HHS) Office for Civil Rights (OCR) and failure to comply with the law will result in punitive damages and other reputational harm. lectricEye does not cover every single control, and only covers the mapping of certain parts of HIPAA requirements defined within Subpart C (Security Rule) to CIS Critical Controls V8 which is mapped to the NIST CSF V1.1 subcategories that all ElectricEye Checks are mapped against. ElectricEye will not contextualize any compensating controls or exceptions that you define.
            """

        # FFIEC Cybersecurity Assessment Tool
        elif framework == "FFIEC Cybersecurity Assessment Tool":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/ffiec_cat.jpg" class="framework__header__image">'
            frameworkInfo = """
            The FFIEC (Federal Financial Institutions Examination Council) Cybersecurity Assessment Tool is a framework developed by the FFIEC to assist financial institutions in evaluating their cybersecurity preparedness and risk management practices. It provides a structured approach for assessing and enhancing an institution's cybersecurity posture and aligning it with industry best practices. The tool helps financial institutions assess their inherent risk profile by considering factors such as their size, complexity, and interconnectedness. It evaluates the potential impact of cybersecurity threats and vulnerabilities on the institution's operations, customers, and stakeholders.</br>
            
            </br>The tool defines four maturity levels (Baseline, Evolving, Intermediate, and Advanced) for each cybersecurity domain. The maturity levels represent different stages of cybersecurity preparedness, ranging from basic control implementation to proactive risk management and continuous improvement. The FFIEC Cybersecurity Assessment Tool is a valuable resource for financial institutions to evaluate and enhance their cybersecurity practices. It assists in identifying potential weaknesses, prioritizing investments in cybersecurity controls, and aligning the institution's risk management efforts with industry standards and expectations.</br>

            </br>As a diagnostic tool, the FFIEC CAT does not have formal examination, accredation, or certification process, and is tailored towards financial institutions within the United States. While it can be useful as a controls framework due to coverage of best practices, ElectricEye reccomends using this framework only if your organization is within the FI industry (or adjacent to it, as a provider). ElectricEye does not cover every single control, and only covers the mapping of FFIEC CAT controls to CIS Critical Controls V8 which is mapped to the NIST CSF V1.1 subcategories that all ElectricEye Checks are mapped against. ElectricEye will not contextualize any compensating controls or exceptions that you define.
            """

        # NERC Critical Infrastructure Protection
        elif framework == "NERC Critical Infrastructure Protection":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/nerc_cip.jpg" class="framework__header__image">'
            frameworkInfo = """
            The NERC CIP (North American Electric Reliability Corporation Critical Infrastructure Protection) is a set of cybersecurity standards developed to protect the critical infrastructure of the electric utility industry in North America. NERC is a not-for-profit international regulatory authority that ensures the reliability and security of the power grid. The NERC CIP standards aim to safeguard the bulk power system (BPS) by establishing requirements for the identification and protection of critical cyber assets. The standards apply to electric utilities, including generation plants, transmission and distribution systems, and other entities involved in the operation and control of the power grid.</br>
            
            </br>The NERC CIP standards apply to all entities that are responsible for the reliable operation of the BPS, including owners, operators, and users of the power grid infrastructure as well as partners and service providers who partner with these organizations. ElectricEye only recommends using the NERC CIP as a controls framework if you work within the United States power or critical infrastructure apparatus. ElectricEye does not cover every single control, and only covers the mapping of NERC CIP controls to CIS Critical Controls V8 which is mapped to the NIST CSF V1.1 subcategories that all ElectricEye Checks are mapped against. ElectricEye will not contextualize any compensating controls or exceptions that you define.
            """

        # NYDFS 23 NYCRR Part 500
        elif framework == "NYDFS 23 NYCRR Part 500":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/nydfs500_title23.jpg" class="framework__header__image">'
            frameworkInfo = """
            Part 500 of Title 23 New York Codes, Rules, and Regulation (also known colloquially as NYDFS500) are a set of cybersecurity requirements on financial institutions that are licensed or authorized to do business in the State of New York created by the New York State Department of Financial Services (NYDFS). NYDFS500 is designed to protect customer data and the information technology systems of financial institutions such as state-chartered, private, and international banks, mortgage brokers, insurance companies, and other financial institutions. It encompasses both individuals and organizations subject to NYDFS oversight. In effect, NYDFS500 is a law much like the Health Insurance Portability and Accountability Act (HIPAA), that defines legal statutes that must be met complied with to avoid punitive damages and other enforcement actions taken upon organizations by the NYDFS</br>

            </br>As NYDFS500 is a legal requirement and not a "pure-play" controls framework or standard, ElectricEye only recommends using the provided mappings if you are subject to NYDFS oversight - in which case you must doubly-ensure ElectricEye Checks are mapped correctly and fulfilled your own internal controls frameworks that satisify the statutes. ElectricEye does not cover every single control, and only covers the mapping of NYDFS 23 NYCRR Part 500 requirements to CIS Critical Controls V8 which is mapped to the NIST CSF V1.1 subcategories that all ElectricEye Checks are mapped against. ElectricEye will not contextualize any compensating controls or exceptions that you define.
            """

        # UK NCSC Cyber Assessment Framework V3.1
        elif framework == "UK NCSC Cyber Assessment Framework V3.1":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/uk_ncsc_caf_v3_1.jpg" class="framework__header__image">'
            frameworkInfo = """
            The United Kingdom's National Cybercrime Securty Centre (NCSC) Cyber Assessment Framework (CAF) provides a systematic and comprehensive approach to assessing the extent to which cyber risks to essential functions are being managed by the organisation responsible. It is intended to be used either by the responsible organisation itself (selfassessment) or by an independent external entity, possibly a regulator or a suitably qualified organisation acting on behalf of a regulator. The NCSC CAF cyber security and resilience principles provide the foundations of the CAF. The 14 principles are written in terms of outcomes, i.e. specification of what needs to be achieved rather than a checklist of what needs to be done. The CAF adds additional levels of detail to the top-level principles, including a collection of structured sets of Indicators of Good Practice (IGPs) as described in more detail below.</br>

            </br>As stated in the National Cyber Strategy, the CAF is being introduced as part of a new programme aimed at improving government cyber security. Outside of government, the organisations likely to find the CAF collection most useful fall into three broad categories, namely: organisations within the UK Critical National Infrastructure (CNI), organisations subject to Network and Information Systems (NIS) Regulations, and organisations managing cyber-related risks to public safety within the United Kingdom. This makes the CAF broadly applicable across industries but ElectricEye recommends picking this framework either if you meet the previously mentioned subjects or are otherwise lacking a controls framework to back your own security program as the CAF is very well written with clear definitions of how you can meet the control objectives. ElectricEye does not cover every single control, and only covers the mapping of the CAF (V3.2) controls (IGPs) to CIS Critical Controls V8 which is mapped to the NIST CSF V1.1 subcategories that all ElectricEye Checks are mapped against. ElectricEye will not contextualize any compensating controls or exceptions that you define.
            """

        # PCI-DSS V4.0
        elif framework == "PCI-DSS V4.0":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/pci_dss_v4_0.jpg" class="framework__header__image">'
            frameworkInfo = """
            PCI-DSS, or Payment Card Industry Data Security Standard, is a set of security standards established to ensure the protection of cardholder data during payment card transactions. It was developed by major credit card companies, including Visa, Mastercard, American Express, Discover, and JCB, to provide a unified framework for securing cardholder information. The PCI Security Standards Council (PCI SSC) issued version 4.0 of the PCI Data Security Standard (PCI DSS) on March 31, 2022. The PCI DSS is a global standard that establishes a baseline of technical and operational standards for protecting account data. PCI DSS v4.0 replaces PCI DSS version 3.2.1 to address emerging threats and technologies better and provide innovative ways to combat new threats. The primary goals of PCI-DSS are to prevent unauthorized access to cardholder data, maintain a secure environment for card transactions, and foster trust and confidence in the payment card industry.</br>

            </br>The PCI-DSS V4.0 standard meant for organizations who process or store any type of Cardholder Data (CHD) and is thus only applicable to certain industries and entities, ElectricEye recommends using this framework if you meet the previously mentioned subjects. The PCI-DSS standard does have a formalized certification process which includes determining the compliance level (based on transacations, for example), self-assessing, engaging a PCI Qualified Security Assessor (QSA) and receiving a Report on Compliance (ROC) along with several technical and administrative tasks and controls that must be fulfilled, along with picking supporting technology which is certified for use within PCI-DSS examinations. ElectricEye does not cover every single control, and only covers the mapping of PCI-DSS V4.0 requirements to CIS Critical Controls V8 which is mapped to the NIST CSF V1.1 subcategories that all ElectricEye Checks are mapped against. ElectricEye can help with readiness for a formalized engagement with a QSA for very specific parts but ElectricEye will not contextualize any compensating controls or exceptions that you define.
            """

        # NZISM V3.5
        elif framework == "NZISM V3.5":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/nzism.jpg" class="framework__header__image">'
            frameworkInfo = """
            The New Zealand Information Security Manual (NZISM) is the New Zealand Government's manual on information assurance and information systems security. The NZISM is a practitioner's manual designed to meet the needs of agency information security executives as well as vendors, contractors and consultants who provide services to agencies. Crown entities, local government bodies, and private sector organisations - particularly vendors seeking to do business with the New Zealnd government - can leverage NZISM to prioritise their cybersecurity roadmap. It contains both a risk management framework and a number of security controls that NZ government agencies are required to have and that many NZ organisations are encouraged to have.</br>

            </br>The NZISM V3.5 (V3.6) controls framework is broadly applicable across industries but only legally required for certain entities within New Zealand as well as external partners wanting to sell their security and IT products and services to the New Zealand government. ElectricEye recommends picking this framework only if you meet the previously mentioned subjects. ElectricEye does not cover every single control, and only covers the mapping of NZISM V3.5 requirements (Blocks, and mapped Control IDs [CIDs]) to CIS Critical Controls V8 which is mapped to the NIST CSF V1.1 subcategories that all ElectricEye Checks are mapped against. ElectricEye can help with readiness for a formalized Accredation & Certification (A&C) process that is defined by the New Zealand Government Communications Security Bureau, but does not take the place of any formal examinations defined by them. ElectricEye will not contextualize any compensating controls or exceptions that you define.
            """

        # ISO 27001:2022
        elif framework == "ISO 27001:2022":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/iso_27001_2022.jpg" class="framework__header__image">'
            frameworkInfo = """
            ISO/IEC 27001 is the world's best-known standard for information security management systems (ISMS) - those are ISO's words - not ElectricEye's! It defines requirements an ISMS must meet, the 27001 standard provides companies of any size and from all sectors of activity with guidance for establishing, implementing, maintaining and continually improving an information security management system. Conformity with ISO/IEC 27001 means that an organization or business has put in place a system to manage risks related to the security of data owned or handled by the company, and that this system respects all the best practices and principles enshrined in this International Standard. Annex A has seen the greatest change. The updated version of ISO 27001 Annex A has been completely restructured and revised. As a result, the number of controls has decreased from 114 to 93 in the new version of ISO 27001. Also, these security controls are now divided into four sections instead of the previous 14.</br>

            </br>As this controls framework is not industry- or environment-specific, and comes with its own examination and certification process, it can be valauble to pursue for nearly any company wanting to publicly demonstrate that their security program and controls follow a well-known best practice. Personally, if you have a SaaS company, customers will ask for this or for SOC 2 Type II examination reports. ElectricEye does not cover every single control, and only covers the mapping of ISO 27001:2022 Annex A requirements to CIS Critical Controls V8 which is mapped to the NIST CSF V1.1 subcategories that all ElectricEye Checks are mapped against, ElectricEye will not contextualize any compensating controls or exceptions that you define.
            """

        # Critical Risk Profile V1.2
        elif framework == "Critical Risk Profile V1.2":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/cri_profile_v12.jpg" class="framework__header__image">'
            frameworkInfo = """
            The Cyber Risk Institute (CRI) is a not-for-profit coalition of financial institutions and trade associations, working to protect the global economy by enhancing cybersecurity and resiliency through standardization. The Cyber Profile tool is the benchmark for cyber security and resiliency in the financial services industry. This ever-evolving and concise list of assessment questions is curated based on the intersection of global regulations and cyber standards, such as ISO and NIST. The (Critical Risk) Profile (V1.2) eases this burden on the financial services industry while still meeting regulatory expectations. Focusing cybersecurity experts' time on protecting global financial platforms, rather than compliance activity, will significantly enhance security efforts. For an industry already burdened by a shortage of adequately skilled individuals, reducing this percentage by streamlining compliance activity is an immediate gain in efficiency and managed risk. For the regulatory community, Profile use would enhance transparency and improve visibility across institutions, subsectors, third-parties, and across sectors, enabling better analysis and mitigation of systemic and concentration risks. When industry can focus on cybersecurity, and when regulators have more confidence in compliance, the consumer benefits.</br>

            </br>This controls framework is largely based on NIST CSF and ISO 27001 Annex A requirements with a mind towards being mapped to financial industry regualtory frameworks and laws, such the the European Central Bank's Cyber Resilience Oversight Expectations (CROEs), the NYDFS 23 NYCRR Part 500, and similar laws and frameworks. If you are a financial industry in one or more regulated locales, using the Critical Risk Profile can be a good analog in lieu of disparate controls monitoring and internal regulatory compliance work efforts. ElectricEye does not cover every single control, and only covers the mapping of Cyber Risk Profile V1.2 to CIS Critical Controls V8 which is mapped to the NIST CSF V1.1 subcategories that all ElectricEye Checks are mapped against. There is not an examination or accredation that goes alongside this controls framework and ElectricEye will not contextualize any compensating controls or exceptions that you define.
            """

        # ECB CROE
        elif framework == "ECB CROE":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/euro_central_bank_croe.jpg" class="framework__header__image">'
            frameworkInfo = """
            The European Central Bank (ECB) Cyber Resilience Oversight Expectations (CROEs) for Finanical Market Infrastructures (FMIs) include an evaluation of cybersecurity and information security, recognizing the critical importance of protecting the ECB's systems and data from cyber threats. This evaluation focuses on assessing the ECB's measures to ensure the confidentiality, integrity, and availability of its information assets. The ECB's oversight responsibilities extend to FMIs operating within the Eurozone, regardless of whether they utilize cloud services or traditional on-premises infrastructure. </br>
            
            </br>In this context, the cyber resilience oversight expectations (CROE) serves the following three key purposes: (i) it provides FMIs with detailed steps on how to operationalise the Guidance, ensuring they are able to foster improvements and enhance their cyber resilience over a sustained period of time; (ii) it provides overseers with clear expectations to assess the FMIs for which they are responsible; and (iii) it provides the basis for a meaningful discussion between the FMIs and their respective overseers.</br>

            </br>This controls framework will only matter if you're managing FMIs within the Eurozone and subject to regulation by the ECB. ElectricEye does not cover every single control, and only covers the ECB CROEs by virtue of their mapping to the Cyber Risk Institute's Cyber Risk Profile V1.2 which in turn is mapped against the CIS Critical Controls V8 which is mapped to the NIST CSF V1.1 subcategories that all ElectricEye Checks are mapped against. This does not take the place of a qualified opinion from an audit organization and it will not contextualize any compensating controls or exceptions that you define.
            """

        # Equifax SCF V1.0
        elif framework == "Equifax SCF V1.0":
            imgSource = '<img src="https://iconography.electriceye.lol/AuditFrameworks/equifax_scf_v1_0.jpg" class="framework__header__image">'
            frameworkInfo = """
            The Equifax Security Controls Framework is a blueprint for how a company can protect its data and infrastructure. Five core capabilities - cybersecurity, privacy, fraud prevention, crisis management, and physical security - are represented in these unified controls framework. NIST CSF and NIST PF were selected as the foundation for the security controls framework because it supports a comprehensive, defense-in-depth approach to security and privacy. Its flexible, risk-based structure can also be tailored to meet a company's specific needs. This controls framework was released to the public domain by the Equifax cybersecurity function in May 2023.</br>

            </br>This controls framework can be used by anyone in any industry as it is broadly based on NIST CSF V1.1 and the controls are meant to help support your security program's data protection and infrastructure security best practices. ElectricEye does not cover every single control, Equifax provides a first-party mapping to the NIST CSF V1.1 subcategories that all ElectricEye Checks are mapped against. There is not an examination or accredation that goes alongside this controls framework and ElectricEye will not contextualize any compensating controls or exceptions that you define.
            """

        else:
            return []

        frameworkHeader = f'''
            <section class="framework__header">
                <figure>{imgSource}</figure>
                <h4>{frameworkInfo}</h4>
            </section>
        '''

        return frameworkHeader

    def html_creation(self, processedFindings, controlsAggregation, assetDataPerControl, outputFile):
        """
        This function assembles an HTML Report of matplotlib SVGs and tables
        """

        dateNow = str(datetime.utcnow()).split(".")[0].split(" ")[0]

        # Beginning of the HTML doc with sytlesheet
        htmlPrefix = f'''
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta http-equiv="X-UA-Compatible" content="ie=edge">
            <title>ElectricEye Compliance Status</title>
        </head>
        <style>
            {self.generate_stylesheet()}
        </style>
        <body>
        <section class="summary__header">
            <figure>
                <img src="https://raw.githubusercontent.com/jonrau1/ElectricEye/master/screenshots/logo.svg" class="summary__header__image">
                <figcaption>ElectricEye Audit Readiness Report -- {dateNow}</figcaption>
            </figure>
            <h4>{self.generate_executive_summary(processedFindings)}</h4>
        </section>
        '''
        # Retrieve the info table contents and the SVG from matplotlib of the bar chart/pie chart for the compliance framework
        for visual in self.create_visuals(controlsAggregation, assetDataPerControl):
            tableContents = visual[0]
            svgImage = visual[1]
            # Generate the section header for a specified framework
            frameworkHeader = self.framework_section_information_generator(visual[2])

            html = f'''
            {frameworkHeader}
            <div class="chart__image">{svgImage}</div>
            <section class="table__body">
                <div class="compliance__info__table">
                <table>
                    <thead>
                        <tr>
                            <th>Control Title</th>
                            <th>Control Objective</th>
                            <th>Control Passing Score</th>
                            <th>Unique Asset Classes Impacted</th>
                            <th>Unique Asset Services Impacted</th>
                            <th>Unique Asset Components Impacted</th>
                            <th>Total Check Evaluations in Scope</th>
                            <th>Passing Controls</th>
                            <th>Failing Controls</th>
                        </tr>
                    </thead>
                <tbody>
            '''
            # Loop the contents of the table to add the rows
            for content in tableContents:
                # Create a <p> with label depending on the "raw score" - 100.0 is the best and 0.0 is the worst.
                percentage = content["PassingPercentage"]
                rawScore = content["RawPassingScore"]
                if rawScore >= 99.0:
                    passingPercentage = f'<td><p class="score great">{percentage}</p></td>'
                elif 70.0 < rawScore < 99.0:
                    passingPercentage = f'<td><p class="score good">{percentage}</p></td>'
                elif 40.0 < rawScore < 70.0:
                    passingPercentage = f'<td><p class="score meh">{percentage}</p></td>'
                elif 15.0 < rawScore < 40.0:
                    passingPercentage = f'<td><p class="score bad">{percentage}</p></td>'
                else:
                    passingPercentage = f'<td><p class="score reallybad">{percentage}</p></td>'
                # Setup the table rows
                newTd = f'''
                    <tr>
                        <td>{content["ControlTitle"]}</td>
                        <td>{content["ControlDescription"]}</td>
                        {passingPercentage}
                        <td>{content["UniqueAssetClass"]}</td>
                        <td>{content["UniqueAssetService"]}</td>
                        <td>{content["UniqueAssetComponent"]}</td>
                        <td>{content["ResourcesImpacted"]}</td>
                        <td>{content["PassingControls"]}</td>
                        <td>{content["FailingControls"]}</td>
                    </tr>
                '''
                html += newTd
            # Close the Table & Section
            html += """
                    </tbody>
                </table> 
            </section>
            """
            htmlPrefix += html
        # Close the Body and HTML tags
        htmlEnd = '''
        <footer>Created by ElectricEye: https://github.com/jonrau1/ElectricEye</footer>
        </body>
        </html>
        '''

        htmlPrefix += htmlEnd

        with open(f"{here}/{outputFile}_audit_readiness_report.html", "w") as f:
            f.write(htmlPrefix)

        print("Finished creating HTML report for audit readiness")

## EOF