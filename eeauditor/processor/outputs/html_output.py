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

import os
from datetime import datetime
import yaml
from processor.outputs.output_base import ElectricEyeOutput
from os import path

here = path.abspath(path.dirname(__file__))

# Get the absolute path of the current directory
currentDir = os.path.abspath(os.path.dirname(__file__))
ICONOGRAPHY_FILE = f"{currentDir}/iconography.yaml"
with open(ICONOGRAPHY_FILE) as f:
    ICONOGRAPHY = yaml.safe_load(f)

@ElectricEyeOutput
class HtmlProvider(object):
    __provider__ = "html"

    def write_findings(self, findings: list, output_file: str, **kwargs):
        if len(findings) == 0:
            print("There are not any findings to write to file!")
            exit(0)

        activeTable = self.process_data(findings)

        tableStructures = self.generate_table_structure(activeTable)

        mainTable = tableStructures[0]
        for row in activeTable:
            # Pull out row details
            findingId = row["Id"]
            createdAt = row["CreatedAt"]
            # Assign dynamic Paragraph CSS class depending on finding sev
            severity = row["Severity"]
            if severity == "CRITICAL":
                severity = f'<p class="severity critical">{severity}</p>'
            elif severity == "HIGH":
                severity = f'<p class="severity high">{severity}</p>'
            elif severity == "MEDIUM":
                severity = f'<p class="severity medium">{severity}</p>'
            elif severity == "LOW":
                severity = f'<p class="severity low">{severity}</p>'
            elif severity == "INFORMATIONAL":
                severity = f'<p class="severity informational">{severity}</p>'
            title = row["Title"]
            description = row["Description"]
            provider = row["Provider"]
            providerAcctId = row["ProviderAccountId"]
            assetRegion = row["AssetRegion"]
            assetClass = row["AssetClass"]
            # Attempt to get the IMG tag of a service
            assetService = row["AssetService"]
            serviceImg = self.get_image_tag(assetService)
            if serviceImg == None:
                assetServiceTd = f"<td>{assetService}</td>"
            else:
                assetServiceTd = f'<td>{serviceImg} \n {assetService}</td>'
            assetComponent = row["AssetComponent"]
            resourceId = row["ResourceId"]
            recordState = row["RecordState"]
            complianceStatus = row["ComplianceStatus"]
            if complianceStatus == "PASSED":
                complianceStatus = f'<p class="compliance passed">{complianceStatus}</p>'
            elif complianceStatus == "FAILED":
                complianceStatus = f'<p class="compliance failed">{complianceStatus}</p>'
            newTd = f'''
                <tr>
                    <td>{findingId}</td>
                    <td>{createdAt}</td>
                    <td>{severity}</td>
                    <td>{title}</td>
                    <td>{description}</td>
                    <td>{provider}</td>
                    <td>{providerAcctId}</td>
                    <td>{assetRegion}</td>
                    <td>{assetClass}</td>
                    {assetServiceTd}
                    <td>{assetComponent}</td>
                    <td>{resourceId}</td>
                    <td>{recordState}</td>
                    <td>{complianceStatus}</td>
                </tr>
                '''
            mainTable += newTd
        
        # Close out the table
        mainTable += tableStructures[1]

        html = f"""
            <html lang="en" title="ElectricEye Executive Report">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <meta http-equiv="X-UA-Compatible" content="ie=edge">
                    <title>ElectricEye Executive Report</title>
                </head>
                <style>{self.generate_stylesheet()}</style>
                <body>
                    <div>
                        {mainTable}
                        <footer>Created by ElectricEye: https://github.com/jonrau1/ElectricEye</footer>
                    </div>
                </body>
            </html>
            """
        with open(f"{here}/{output_file}_executive_report.html", "w") as f:
            f.write(html)

        print("HTML executive report created!")

        return True
    
    def process_data(self, findings):
        """
        This function processes and normalizes all findings into 13 k:v pairs needed for the HTML executive report.
        The function then sorts the new list into descending order by severity, and finally, returns the new
        list of findings for use in the report.
        """

        executiveReportFindings = []

        for finding in findings:
            try:
                dt = datetime.fromisoformat(finding["CreatedAt"])
                executiveReportFindings.append(
                    {
                        "Id": finding["Id"],
                        # Converts to "15 MARCH 2022" format
                        "CreatedAt": dt.strftime("%d %B %Y"),
                        "Severity": finding["Severity"]["Label"],
                        "Title": finding["Title"],
                        "Description": finding["Description"],
                        "Provider": finding["ProductFields"]["Provider"],
                        "ProviderAccountId": finding["ProductFields"]["ProviderAccountId"],
                        "AssetRegion": finding["ProductFields"]["AssetRegion"],
                        "AssetClass": finding["ProductFields"]["AssetClass"],
                        "AssetService": finding["ProductFields"]["AssetService"],
                        "AssetComponent": finding["ProductFields"]["AssetComponent"],
                        "ResourceId": finding["Resources"][0]["Id"],
                        "RecordState": finding["RecordState"],
                        "ComplianceStatus": finding["Compliance"]["Status"]
                    }
                )
            except KeyError:
                continue

        print(f"Processed {len(executiveReportFindings)} findings for executive report")
        # 0 is highest, 4 lowest
        severityOrder = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFORMATIONAL": 4
        }
        # Apply the sort order based on Seveirty
        def reorder(item):
            return severityOrder.get(item["Severity"], 5)
        
        del findings

        sortedList = sorted(
            executiveReportFindings,
            key=reorder
        )

        del executiveReportFindings

        return sortedList
    
    def generate_stylesheet(self):
        """
        This function creates an f-string Stylesheet and returns it to be added into a HTML Doc F-string
        for saving too a file. All styles of the tables live here.
        """

        stylesheet = '''
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: sans-serif;
        }

        body {
            min-height: 100vh;
            background: linear-gradient(to bottom, #6B0000, #555555);
            background-repeat: no-repeat;
            background-attachment: fixed;
            background-size: 100%;
            display: flex;
            justify-content: center;
            align-items: center;
        }

        main.table {
            width: 82vw;
            height: 90vh;
            background-color: #fff5;

            backdrop-filter: blur(7px);
            box-shadow: 0 .4rem .8rem #0005;
            border-radius: .8rem;

            overflow: hidden;
        }

        .table__header {
            width: 100%;
            height: 20%;
            background-color: #d5d1defe;
            padding: .8rem 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .table__body {
            width: 95%;
            max-height: calc(79% - 1.6rem);
            background-color: #fffb;

            margin: .8rem auto;
            border-radius: .6rem;

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

        table {
            width: 100%;
        }

        td img {
            width: 64px;
            height: 64px;
            margin-right: .5rem;
            vertical-align: middle;
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
            background-color: #009879;
        }

        thead tr {
            border-bottom: 2px solid #dddddd;
        }

        tbody tr:nth-child(even) {
            background-color: #0000000b;
        }

        .severity {
            padding: .4rem 0;
            border-radius: 2rem;
            text-align: center;
        }

        .severity.critical {
            background-color: rgb(214, 63, 56);
            color: #ffc400;
        }

        .severity.high {
            background-color: rgb(254, 110, 115);
            color: #fff;
        }

        .severity.medium {
            background-color: rgb(248, 146, 86);
        }

        .severity.low {
            background-color: rgb(223, 181, 44);
        }

        .severity.informational {
            background-color: #d5dbdb;
        }

        .compliance {
            padding: .4rem 0;
            border-radius: 2rem;
            text-align: center;
        }

        .compliance.passed {
            background-color: #6aaf35;
            color: white;
        }

        .compliance.failed {
            background-color: #fe6e73;
            color: white;
        }

        footer {
            height: 1.5rem; /* Footer height */
            text-align: center;
            color: white;
        }
        '''

        return stylesheet

    def generate_table_structure(self, processedData):
        """
        This function generates the HTML structure required for the tables
        """

        dateNow = str(datetime.utcnow()).split(".")[0]
        execSummary = self.generate_stats(processedData)

        tableStructure = f'''
            <main class="table">
                <section class="table__header">
                    <h1>ElectricEye Executive Report as of {dateNow}</h1>
                    <p class="writeup">{execSummary}</p>
                </section>
                <section class="table__body">
                    <table>
                        <thead>
                            <tr>
                                <th>Finding ID</th>
                                <th>Created At</th>
                                <th>Severity</th>
                                <th>Title</th>
                                <th>Description</th>
                                <th>Provider</th>
                                <th>Provider Account ID</th>
                                <th>Asset Region</th>
                                <th>Asset Class</th>
                                <th>Asset Service</th>
                                <th>Asset Component</th>
                                <th>Resource ID</th>
                                <th>Finding State</th>
                                <th>Compliance Status</th>
                            </tr>
                        </thead>
                    <tbody>
        '''
        # After this section, multiple table rows need to be added, before it's closed out
        tableClosure = f'''
                    </tbody>
                </table>
            </section>
        </main>
        '''

        return tableStructure, tableClosure

    def get_image_tag(self, service):
        """
        This function returns an <img> tag from a public source to match an AssetService based on records in a YAML
        """

        for asset in ICONOGRAPHY:
            if asset["AssetService"] == service:
                if asset["ImageTag"] == "placeholder":
                    return None
                else:
                    return asset["ImageTag"]
        
        return None

    def generate_stats(self, processedData):
        """
        This functions analyzes a group of ElectricEye findings and will return high level stats about it for an executive summary
        in the report and return the value to the table generator function to embed it as an HTML object
        """

        # Total
        totalFindings = len(processedData)
        # Compliance Passed v Failed
        totalPassed = [finding for finding in processedData if finding["ComplianceStatus"] == "PASSED"]
        totalFailed = [finding for finding in processedData if finding["ComplianceStatus"] == "FAILED"]

        passingPercentage = (len(totalPassed) / totalFindings) * 100
        roundedPercentage = f"{round(passingPercentage, 2)}%"
        # Severity Status
        criticalsFindings = [finding for finding in processedData if finding["Severity"] == "CRITICAL"]
        highFindings = [finding for finding in processedData if finding["Severity"] == "HIGH"]
        mediumFindings = [finding for finding in processedData if finding["Severity"] == "MEDIUM"]
        lowFindings = [finding for finding in processedData if finding["Severity"] == "LOW"]
        infoFindings = [finding for finding in processedData if finding["Severity"] == "INFORMATIONAL"]
        # Resource IDs
        #allResources = [d.get("ResourceId") for d in processedData]
        uniqueResource = list(set(d.get("ResourceId") for d in processedData))
        # Assets
        #allServices = [d.get("AssetService") for d in processedData]
        uniqueClasses = list(set(d.get("AssetClass") for d in processedData))
        uniqueServices = list(set(d.get("AssetService") for d in processedData))
        #allComponents = [d.get("AssetComponent") for d in processedData]
        uniqueComponents = list(set(d.get("AssetComponent") for d in processedData))
        # Accounts
        uniqueAccounts = list(set(d.get("ProviderAccountId") for d in processedData))
        # Regions
        uniqueRegions = list(set(d.get("AssetRegion") for d in processedData))

        executiveReport = f'ElectricEye Auditors scanned {len(uniqueResource)} total Assets across {len(uniqueAccounts)} Provider Account(s) in {len(uniqueRegions)} Region(s)/Zone(s) \
            and generated {totalFindings} Findings. Of all findings, {len(totalFailed)} failed and {len(totalPassed)} passed for an ElectricEye Findings Passing Score of {roundedPercentage}. \
            Of these findings the severities are {len(criticalsFindings)} Critical, {len(highFindings)} High, {len(mediumFindings)} Medium, {len(lowFindings)} Low, and {len(infoFindings)} Informational. \
            There are {len(uniqueClasses)} Asset Classes (categories) across the Provider Accounts & Regions, comprising {len(uniqueServices)} distinct Asset Services and {len(uniqueComponents)} distinct \
            Asset Components. It is recommended to work backwards from resources with the highest amount of failed findings and Assets with important business- or mission-criticality.'
        
        return executiveReport

# EOF