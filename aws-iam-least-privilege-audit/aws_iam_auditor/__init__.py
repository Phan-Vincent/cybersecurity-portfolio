"""
AWS IAM Least-Privilege Auditor

A security tool that audits AWS IAM configurations for overly permissive
permissions, unused credentials, missing MFA, and over-privileged roles.

Supports both live AWS auditing (read-only via boto3) and offline mock mode
with synthetic data for safe testing and demonstration.
"""

__version__ = "1.0.0"
__author__ = "Vincent Phan"
