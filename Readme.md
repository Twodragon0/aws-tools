# Cloud Security Review Guidelines

This document outlines critical security considerations tailored to Public Cloud environments such as AWS, Azure, and Google Cloud Platform (GCP). The guidelines aim to ensure the security and integrity of systems and data by addressing specific security aspects of each cloud platform.

## AWS Security Considerations

###Asset Trading Service Development or Modification
- Ensure secure configuration of hosting services (EC2, RDS, VPC) and implement data encryption using AWS Key Management Service (KMS) or Certificate Manager.

### Integration with External Organizations for Electronic Transactions
- Use AWS Direct Connect or AWS VPN for secure communication channels and manage access with AWS Identity and Access Management (IAM) enforcing least privilege.

### Significant Changes in Network Configuration
- Manage traffic with AWS Security Groups and NACLs. Monitor changes and detect unauthorized access with AWS CloudTrail.

### New Integration for Internet Segments
- Protect web applications using AWS Web Application Firewall (WAF) and defend against DDoS attacks with AWS Shield.

### Implementation and Installation of Security Systems
- Monitor for malicious activity with AWS GuardDuty and manage security compliance across AWS accounts with AWS Security Hub.

### New Business Involving Handling of Customer Personal Information
- Ensure compliance with data protection regulations (GDPR, HIPAA) using encryption, access controls, and Amazon S3 Object Lock.

## Azure Security Considerations

###Asset Trading Service Development or Modification
- Secure Azure Virtual Machines with Network Security Groups (NSGs) and Azure Firewall. Manage cryptographic keys with Azure Key Vault.

### Integration with External Organizations for Electronic Transactions
- Establish secure connections with Azure Virtual Network Gateway or Azure ExpressRoute and manage identities with Azure Active Directory (AD).

### Significant Changes in Network Configuration
- Assess and monitor security posture with Azure Security Center and enforce compliance with Azure Policy.

### New Integration for Internet Segments
- Use Azure Application Gateway with WAF for web application protection and defend against DDoS attacks with Azure DDoS Protection Standard.

### Implementation and Installation of Security Systems
- Enable continuous threat detection with Azure Security Center and Azure Defender, and manage SIEM with Azure Sentinel.

### New Business Involving Handling of Customer Personal Information
- Protect sensitive data in compliance with regulatory requirements using Azure Information Protection and Azure Disk Encryption.

## GCP Security Considerations

###Asset Trading Service Development or Modification
- Secure Google Compute Engine instances with Firewall Rules and VPC Service Controls, and manage keys with Google Cloud KMS.

### Integration with External Organizations for Electronic Transactions
- Use Cloud VPN or Dedicated Interconnect for secure partner connections and manage identities with Google Cloud Identity Platform.

### Significant Changes in Network Configuration
- Gain visibility into security threats with Google Cloud Security Command Center and protect internet-facing applications with Google Cloud Armor.

### New Integration for Internet Segments
- Identify web application vulnerabilities with Google Cloud Web Security Scanner and ensure secure communication with HTTPS load balancing.

### Implementation and Installation of Security Systems
- Monitor threats with Security Health Analytics in Google Cloud Security Command Center and enforce security controls with Google Cloud Armor Security Policies.

### New Business Involving Handling of Customer Personal Information
- Classify, redact, and protect sensitive data with Google Cloud Data Loss Prevention (DLP) and encrypt data with Google Cloud Encryption Keys.

These guidelines serve as a foundation for conducting thorough security reviews in cloud environments, ensuring comprehensive protection of infrastructure, applications, and data.
