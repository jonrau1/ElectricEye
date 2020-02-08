# ElectricEye
Scans your AWS serivces for misconfigurations that can lead to degradation of confidentiality, integrity or availability. All results will be sent to Security Hub for further aggregation and analysis. 

***Up here in space***<br/>
***I'm looking down on you***<br/>
***My lasers trace***<br/>
***Everything you do***<br/>
*Judas Priest, 1982*

## Description
ElectricEye is a set of Python scripts that use boto3 to scan your AWS infrastructure looking for security and availability configurations that do not align with AWS best practices. Services that fail these checks will have findings for them sent to AWS Security Hub, where you perform basic correlation against other AWS and 3rd Party services that send findings to Security Hub and have a centralized view from which account owners and other responsible parties can view them.

ElectricEye runs on AWS Fargate, which is a serverless container orchestration platform. You will build and push a Docker image and use Terraform to create all necessary components needed for ElectricEye to perform its scans. You can set how often you want the scans to happen, and all findings will link to relevant AWS documentation to give you information on how to remediate potential misconfigurations.

Personas who can make use of this tool are DevOps/DevSecOps engineers, SecOps analysts, Enterprise Architects, SREs, Internal Audit and/or Compliance Analysts.

ElectricEye scans 12 different AWS services such as AppStream 2.0, AMIs and Managed Kafka Service clusters and supports 41 unique checks across all services. More checks and services will be added periodically.

## Solution Architecture
TBD

## Setting Up
TBD

## FAQ
##### 1. Why should I use this tool?
Primarily because it is free. This tool will also help cover services not currently covered by Amazon GuardDuty or AWS Security Hub compliance standards. This tool is also natively integrated with Security Hub, no need to create additional services to perform translation into the AWS Security Finding Format and calling the BatchImportFindings API to send findings to Security Hub.

2. Will this tool help me become compliant with (insert regulatory framework here)?
No. If you wanted to use this tool to satisfy an audit, I would recommend you work closely with your GRC and Legal functions to determine if the checks performed by ElectricEye will legally satisfy the requirements of any compliance framework or regulations you need to comply with.

If you find that it does, you can use `Compliance.RelatedRequirements` to denote those. I would recommend forking and modifying the code for that purpose.

3. Can this be the primary tool I use for AWS security scanning?
Only you can make that determination. More is always better, there are far more mature projects that exist such as [Prowler](https://github.com/toniblyx/prowler), [PacBot](https://github.com/tmobile/pacbot), [Cloud Inquisitor](https://github.com/RiotGames/cloud-inquisitor) and [Scout2](https://github.com/nccgroup/ScoutSuite). 

You should perform a detailed analysis about which tools support what checks, what your ultimate downstream tool will be for taking actions or analyzing findings (Splunk, Kibana, Security Hub, etc.) and how many false-positives or false-negatives are created by what tool.

4. Why didn't you build Config rules do these?
Mainly because I couldn't get RDK working to save my life, and I do not know how to.

I built ElectricEye with Security Hub in mind, using custom Config rules would require a lot of additional infrastructure and API calls to parse out a specific rule, map what little information Config gives to the ASFF and also perform more API calls to enrich the findings and send it, that is not something I would want to do.

5. What are the advantages over AWS Security Hub compliance standards? Why shouldn't I use those instead?
You should use them! The only notable "advantage" would be ElectricEye might support a resource before a Security Hub compliance standard does, or it may support a check that Security Hub compliance standards do not.

6. What are the advantages over Config Conformance Packs? Why shouldn't I use those instead?
Similar to above, ElectricEye may support another service or another type of check that Config rules do not. You should keep using Conformance Packs if you already do, there are some awesome ARG-powered Config Rules in IAM that ElectricEye would never support.

7. Can I scope these checks by tag or by a certain resource?
No. That is a great idea for a PR though.

8. Why do I have to set this up per account? Why can't I just scan all of my resources across all accounts?
Doing these scans per accounts let your on-call / account owner to view it within their own Security Hub versus not knowing they are potentially using dangerous configurations. Security should be democratized.

Also, that's like...really hard. Good idea for a PR though.

9. Why don't you support (insert service name here)?
I will, eventually. Open up an issue if you really want it or open up a PR if you figured it out.

10. Where is that automated remediation you like so much?
You probably have me confused with someone else...

That is a Phase 2 after I am done scanning all the things, we can remediate all of the things.