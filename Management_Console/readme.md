# AWS Management Console Access Security - Enforcing MFA

## Overview

This document outlines the requirements and steps for enforcing Multi-Factor Authentication (MFA) when accessing the AWS Management Console. This security measure is crucial for enhancing the protection of cloud resources and adhering to legal and regulatory standards.

### Relevant Legislation

- [Technical and Administrative Protective Measures for Personal Information Article 4, Paragraph 4](https://www.law.go.kr/행정규칙/(개인정보보호위원회)개인정보의기술적·관리적보호조치기준/(2021-3,20210915)/제4조)
- [Standards for Securing Safety of Personal Information Article 6, Paragraph 2](https://www.law.go.kr/행정규칙/(개인정보보호위원회)개인정보의안전성확보조치기준/(2021-2,20210915)/제6조)

The management console is considered a gateway that enables access to personal information processing systems (WEB, WAS, DB), and therefore these regulations are applicable.

### Background

Given the nature of cloud services, management console access is possible from any internet-enabled environment, necessitating the application of secondary authentication (MFA) for access control.

#### Example Incident

- [AWS incident leading to personal information leakage at Yanolja and other companies, resulting in fines](https://zdnet.co.kr/view/?no=20210929131738)

## Vulnerability Assessment Criteria

- **Vulnerable**: Not applying MFA for root and IAM account logins to the management console.
- **Not Vulnerable**: Applying MFA for root and IAM account logins to the management console.

## How to Check for Vulnerabilities

### Individual Account Verification

1. Log in to the management console with a root or IAM account.
2. Click on the account name at the top right corner.
3. Click on **Security Credentials**.
4. Check the assignment status under **Multi-Factor Authentication (MFA)**.

### Verification via IAM Service

1. Log in with a root or IAM account that has IAM service permissions.
2. Search for **IAM** in services → Click on **Users** in the left menu.

### Verification via AWS CLI

1. Use the Access key of an account with IAM permissions to execute commands in AWS CLI:

    ```bash
    aws iam generate-credential-report 
    aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,4,8
    ```

2. Check for the `mfa_active` column set to true.

## Remediation Steps

### Individual Account Remediation

1. Log in to the management console with a root or IAM account.
2. Click on the account name at the top right corner.
3. Click on **Security Credentials**.
4. In the **Multi-Factor Authentication (MFA)** section, click on **Assign MFA device**.

### Remediation via IAM Service

1. Log in with a root or IAM account that has IAM service permissions.
2. Search for **IAM** in services → Click on **Users** in the left menu.
3. Click on the account name you wish to assign MFA.
4. In the **Security Credentials** tab, manage the **Assigned MFA device**.

## Reference

- [CIS AWS Benchmark v1.4.0](https://www.cisecurity.org/benchmark/amazon_web_services)

This guide is intended for organizations using AWS to ensure their management console access is secured with MFA, adhering to best practices and regulatory requirements.
