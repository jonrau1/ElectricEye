# ElectricEye Frequently Asked Questions (FAQ)

This is done Amazonian-style, which is to say, none of these questions are frequently asked and are supposed to help Product Managers figure out if their ideas are good...

That said, some of these questions do get asked. So, you're welcome.

## Table of Contents

- [1. What is ElectricEye?](#1-what-is-electriceye)
- [2. Who should use ElectricEye?](#2-who-should-use-electriceye)
- [3. Why should someone use ElectricEye?](#3-why-should-someone-use-electriceye)
- [4. Is ElectricEye a CSPM?](#4-is-electriceye-a-cspm)
- [5. Is ElectricEye a SSPM?](#5-is-electriceye-a-sspm)
- [6. Is ElectricEye a CIEM?](#6-is-electriceye-a-ciem)
- [7. Is ElectricEye a SIEM?](#7-is-electriceye-a-siem)
- [8. Is ElectricEye an Audit / Compliance Tool?](#8-is-electriceye-an-audit--compliance-tool)
- [9. What is "Audit Readiness" ?](#9-what-is-audit-readiness)

## 1. What is ElectricEye?

ElectricEye is an agentless Python Command Line Interface (CLI) tool that scans and evaluates Cloud Service Providers (CSPs) and Software-as-a-Service (SaaS) Vendors for service-level configurations. ElectricEye generates a passing or failing finding per resource across multiple checks that align to seucirty posture management best practices as well as other hygeine checks such as resiliency, recovery, performance optimization, and monitoring. ElectricEye covers popular providers such as AWS, GCP, ServiceNow, and more.

## 2. Who should use ElectricEye?

ElectricEye can be used by any persona within a cloud organization in the security or IT functions such as (but not limited to) Security Engineers, Dev(Sec)Ops Engineers, SREs/Platform Engineers, Architects (various flavors), Governance/Risk/Compliance Analysts, SOC/SecOps Analysts, Cloud Advisors, Offensive Security (Red/Blue/Purple) Teams, and 3rd Party Risk Management Analysts. ElectricEye can also be used by IT Operations, Technology Business Management/ITFM Analysts, and Business Continuity Analysts, and Asset Managers as ElectricEye offers native Cloud Asset Management capabilities.

## 3. Why should someone use ElectricEye?

ElectricEye should be used by anyone wanting to ensure their cloud vendors and their full breadth of services are configured to ensure the best security hygeine. ElectricEye has the most service coverage offering and is the only dual-use Security Posture Management (SPM) tool that is offered for free for both Cloud Security Posture Management (CSPM) and SaaS Security Posture Management (SSPM). ElectricEye also comes with built-in secrets detection and External Attack Surface Management (EASM) capabilities as well as Cloud Asset Management (CAM) with its own hierarchy to support cross-cloud, cross-boundary asset management and reporting.

## 4. Is ElectricEye a CSPM?

Yes, ElectricEye is a Cloud Security Posture Management (CSPM) tool, it provides API-based (agentless) scans of cloud infrastructure and ensures services are configured to best practices.

## 5. Is ElectricEye a SSPM?

Yes, ElectricEye is a SaaS Security Posture Management (SSPM) tool, it provides API-based (agentless) scans of SaaS vendor APIs and ensures users and services are configured to best practices.

## 6. Is ElectricEye a CIEM?

No, ElectricEye is not a Cloud Infrastructure Entitlement Management (CIEM) tool, while ElectricEye does provide several Identity & Access Management checks and does per-user evaluations for MFA, password rotation, and permissions minimization it is not a CIEM. ElectricEye does not have widespread policy evaluation across multiple identity brokers, providers, and boundaries nor does ElectricEye provide any remediation or Just In Time (JIT) entitlements management capabilities.

## 7. Is ElectricEye a SIEM?

No, ElectricEye is not a Security Information & Event Management (SIEM) tool. SIEM tools are used to collect, index, and correlate logs, security events, and other semi-structured and structured data for security operations use cases. While ElectricEye findings can be sent to a SIEM, ElectricEye is not a SIEM in its own right.

## 8. Is ElectricEye an Audit / Compliance Tool?

No, ElectricEye is not *directly* an Audit or Compliance tool. While every finding is mapped into popular and well-used security compliance regimes such as NIST CSF v1.1 and AICPA 2020 TSCs, ElectricEye only provides best-effort mappings for controls and is not the same as an Auditor or other qualified assessor auditing your environment. ElectricEye can be used as an audit readiness or preparedness tool, you could take samples of findings if the cloud infrastructure controls are important to your overall security program. Controls are technical or administrative (i.e., policy or procedure) countermeasures designed to protect the desired outcomes of a security or privacy program. Controls protect the confidentiality, integrity, and availability of information systems. ElectricEye can help determine if the configurations of your cloud infrastructure meets the "spirit" of the controls but is **NOT** the same as an attestation, certification, or some other occult ritual.

## 9. What is "Audit Readiness" ?

ElectricEye uses the term Audit Readiness when communicating the intended use cases for its control frameworks mappings. ElectricEye could be used by qualified assessors to evaluate your environment, it could be used by you to provide as evidence to assessors, but it's best used case is preparing or seeing your readiness for an audit. However, you should already have your own internal controls defined and your own configuration management strategy when it comes to implementing controls. For instance, you may decide it costs too much money and does not offer many security benefits to encrypt all your SQS Queues with AWS KMS CMKs, you have to do that "groundwork" before using ElectricEye to support your internal GRC processes.

## 10. What control frameworks does ElectricEye support?

The controls frameworks that ElectricEye supports is always being updated as newer versions and mappings are available, as of 1 FEB 2024 the following frameworks and legal requirements are supported.

- NIST Cybersecurity Framework Version 1.1
- NIST Special Publication 800-53 Revision 4
- NIST Special Publication 800-53 Revision 5
- NIST Special Publication 800-171 Revision 2
- American Institute of Certified Public Accountants (AICPA) Trust Service Criteria (TSC) 2017/2020 for SOC 2
- ISO/IEC 27001:2013/2017 Annex A
- ISO/IEC 27001:2022 Annex A
- Center for Internet Security (CIS) Critical Security Controls Version 8
- Cloud Security Alliance (CSA) Cloud Controls Matrix (CCM) Version 4.0
- United States Department of Defense Cybersecurity Maturity Model Certification (CMMC) Version 2.0
- United States Federal Bureau of Investigation (FBI) Criminal Justice Information System (CJIS) Security Policy Version 5.9
- United Kingdom National Cybercrime Security Center (NCSC) Cyber Essentials Version 2.2
- United Kingdom National Cybercrime Security Center (NCSC) Assessment Framework Version 3.1
- HIPAA "Security Rule" U.S. Code 45 CFR Part 164 Subpart C
- Federal Financial Institutions Examination Council (FFIEC) Cybersecurity Assessment Tool (CAT)
- North American Electric Reliability Corporation (NERC) Critical Infrastructure Protection (CIP) Standard
- New Zealand Information Security Manual Version 3.5
- New York Department of Financial Services (NYDFS) Series 23 NYCRR Part 500; AKA NYDFS500
- Critical Risk Institue (CRI) Critical Risk Profile Version 1.2
- European Central Bank (ECB) Cyber Resilience Oversight Expectations (CROEs)
- Equifax Security Controls Framework Version 1.0
- Payment Card Industry (PCI) Data Security Standard (DSS) Version 4.0