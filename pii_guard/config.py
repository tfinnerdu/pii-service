"""
pii_guard.config - Dynamic, file-driven configuration for pii-service.

Loaded from PII_CONFIG_FILE (path to a JSON file). If not set, defaults are used.
Allows institutions to customize:
  - Per-entity score thresholds (override the global threshold for specific entity types)
  - Custom regex patterns (additional recognizers beyond the built-in set)
  - Schema profiles (field-name -> entity type hints for specific ERP schemas)
  - Pseudonymization pools (custom fake name/city lists)
  - Policy overrides (extend built-in policies or define custom ones)

Config file format (JSON):
{
  "entity_thresholds": {
    "STUDENT_ID": 0.8,
    "FERPA_MARKER": 0.6
  },
  "custom_patterns": [
    {
      "entity_type": "EMPLOYEE_ID",
      "patterns": [
        { "name": "emp_id", "regex": "\\bEMP-\\d{5}\\b", "score": 0.9 }
      ],
      "context": ["employee", "staff", "faculty"]
    }
  ],
  "schema_profiles": {
    "banner_student": {
      "description": "Ellucian Banner student record fields",
      "field_hints": {
        "PIDM": "STUDENT_ID",
        "SPRIDEN_ID": "STUDENT_ID",
        "GOBTPAC_EXTERNAL_USER": "DOANE_EMAIL",
        "SPRIDEN_LAST_NAME": "PERSON",
        "SPRIDEN_FIRST_NAME": "PERSON",
        "SPBPERS_SSN": "US_SSN",
        "SPBPERS_BIRTH_DATE": "DATE_OF_BIRTH",
        "GOREMAL_EMAIL_ADDRESS": "EMAIL_ADDRESS",
        "SPRTELE_PHONE_AREA": "PHONE_NUMBER"
      },
      "default_mode": "mask"
    }
  },
  "pseudo_pools": {
    "first_names": ["Alex", "Jordan", "Casey"],
    "last_names": ["Smith", "Jones", "Williams"],
    "cities": ["Lincoln", "Omaha", "Kearney"]
  }
}
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("pii_guard.config")


# ---------------------------------------------------------------------------
# Built-in schema profiles — known ERP/SIS field name mappings
# ---------------------------------------------------------------------------

BUILT_IN_SCHEMA_PROFILES: dict[str, dict] = {
    "banner_student": {
        "description": "Ellucian Banner student record — common SPRIDEN/SPBPERS field names",
        "field_hints": {
            "PIDM":                    "STUDENT_ID",
            "SPRIDEN_ID":              "STUDENT_ID",
            "SPRIDEN_LAST_NAME":       "PERSON",
            "SPRIDEN_FIRST_NAME":      "PERSON",
            "SPBPERS_SSN":             "US_SSN",
            "SPBPERS_BIRTH_DATE":      "DATE_OF_BIRTH",
            "GOBTPAC_EXTERNAL_USER":   "DOANE_EMAIL",
            "GOREMAL_EMAIL_ADDRESS":   "EMAIL_ADDRESS",
            "SPRTELE_PHONE_AREA":      "PHONE_NUMBER",
            "SPRTELE_PHONE_NUMBER":    "PHONE_NUMBER",
            "SPRADDR_STREET_LINE1":    "LOCATION",
            "SPRADDR_CITY":            "LOCATION",
            "SPRADDR_ZIP":             "LOCATION",
        },
        "default_mode": "mask",
    },
    "colleague_person": {
        "description": "Ellucian Colleague PERSON record — typical field names from Ethos EEDM",
        "field_hints": {
            "id":                       "COLLEAGUE_ID",
            "colleaguePersonId":        "COLLEAGUE_ID",
            "bannerId":                 "STUDENT_ID",
            "lastName":                 "PERSON",
            "firstName":                "PERSON",
            "fullName":                 "PERSON",
            "preferredName":            "PERSON",
            "emailAddress":             "EMAIL_ADDRESS",
            "phoneNumber":              "PHONE_NUMBER",
            "dateOfBirth":              "DATE_OF_BIRTH",
            "socialSecurityNumber":     "US_SSN",
            "visaType":                 "IMMIGRATION_STATUS",
            "citizenshipCountry":       "NRP",
            "veteranStatus":            "VETERAN_STATUS",
            "disabilityIndicator":      "DISABILITY_ACCOMMODATION",
        },
        "default_mode": "mask",
    },
    "salesforce_contact": {
        "description": "Salesforce Education Cloud Contact / Person Account fields",
        "field_hints": {
            "FirstName":               "PERSON",
            "LastName":                "PERSON",
            "Name":                    "PERSON",
            "Email":                   "EMAIL_ADDRESS",
            "MobilePhone":             "PHONE_NUMBER",
            "Phone":                   "PHONE_NUMBER",
            "Birthdate":               "DATE_OF_BIRTH",
            "MailingStreet":           "LOCATION",
            "MailingCity":             "LOCATION",
            "MailingPostalCode":       "LOCATION",
            "SIS_ID__c":               "STUDENT_ID",
            "Ethos_Guid__c":           "COLLEAGUE_ID",
            "SSN__c":                  "US_SSN",
        },
        "default_mode": "mask",
    },
    "ethos_person": {
        "description": "Ethos Integration Layer persons EEDM resource shape",
        "field_hints": {
            "fullName":                "PERSON",
            "firstName":               "PERSON",
            "lastName":                "PERSON",
            "preferredName":           "PERSON",
            "emailAddress":            "EMAIL_ADDRESS",
            "phoneNumber":             "PHONE_NUMBER",
            "dateOfBirth":             "DATE_OF_BIRTH",
            "colleaguePersonId":       "COLLEAGUE_ID",
            "bannerId":                "STUDENT_ID",
            "gender":                  "NRP",
            "race":                    "NRP",
            "ethnicity":               "NRP",
            "visaType":                "IMMIGRATION_STATUS",
            "disabilityIndicator":     "DISABILITY_ACCOMMODATION",
        },
        "default_mode": "mask",
    },
    "n8n_generic": {
        "description": "Generic field names common in n8n workflows and webhook payloads",
        "field_hints": {
            "email":                   "EMAIL_ADDRESS",
            "phone":                   "PHONE_NUMBER",
            "name":                    "PERSON",
            "full_name":               "PERSON",
            "first_name":              "PERSON",
            "last_name":               "PERSON",
            "ssn":                     "US_SSN",
            "social_security":         "US_SSN",
            "dob":                     "DATE_OF_BIRTH",
            "birth_date":              "DATE_OF_BIRTH",
            "address":                 "LOCATION",
            "student_id":              "STUDENT_ID",
            "notes":                   None,  # None = scan all entity types
            "comments":                None,
            "bio":                     None,
            "description":             None,
        },
        "default_mode": "mask",
    },
    "conductor_ethos": {
        "description": "Orkes Conductor workflow — Ethos change notification input shape",
        "field_hints": {
            "resource.id":             "COLLEAGUE_ID",
            "resource.content.id":     "COLLEAGUE_ID",
            "notes":                   None,
            "comments":                None,
        },
        "default_mode": "mask",
    },
    "workday_hr": {
        "description": "Workday HCM worker record — common field names from Workday SOAP/REST API",
        "field_hints": {
            "Worker_ID":                    "COLLEAGUE_ID",
            "Employee_ID":                  "COLLEAGUE_ID",
            "National_Identifier":          "US_SSN",
            "Social_Security_Number":       "US_SSN",
            "Legal_Name_First_Name":        "PERSON",
            "Legal_Name_Last_Name":         "PERSON",
            "Known_As_First_Name":          "PERSON",
            "Email_Address":                "EMAIL_ADDRESS",
            "Phone_Number":                 "PHONE_NUMBER",
            "Date_of_Birth":                "DATE_OF_BIRTH",
            "Home_Address_Line_1":          "LOCATION",
            "Home_City":                    "LOCATION",
            "Home_Postal_Code":             "LOCATION",
            "Emergency_Contact_Name":       "PERSON",
            "Emergency_Contact_Phone":      "PHONE_NUMBER",
            "Bank_Account_Number":          "FINANCIAL_ACCOUNT",
            "Routing_Number":               "FINANCIAL_ACCOUNT",
            "body":                         None,
            "content":                      None,
        },
        "default_mode": "mask",
    },
    "servicenow_itsm": {
        "description": "ServiceNow ITSM ticket fields — incident, request, and task records",
        "field_hints": {
            "caller_id.name":              "PERSON",
            "caller_id.email":             "EMAIL_ADDRESS",
            "opened_by.name":              "PERSON",
            "assigned_to.name":            "PERSON",
            "short_description":           None,
            "description":                 None,
            "comments":                    None,
            "work_notes":                  None,
            "additional_comments":         None,
            "close_notes":                 None,
            "u_requester_name":            "PERSON",
            "u_requester_email":           "EMAIL_ADDRESS",
            "contact_type":                None,
            "location.name":               "LOCATION",
        },
        "default_mode": "redact",
    },
    "slate_crm": {
        "description": "Technolutions Slate CRM — applicant and student prospect record fields",
        "field_hints": {
            "first":                        "PERSON",
            "last":                         "PERSON",
            "full_name":                    "PERSON",
            "preferred_name":               "PERSON",
            "email":                        "EMAIL_ADDRESS",
            "mobile":                       "PHONE_NUMBER",
            "ssn":                          "US_SSN",
            "dob":                          "DATE_OF_BIRTH",
            "address1":                     "LOCATION",
            "city":                         "LOCATION",
            "zip":                          "LOCATION",
            "visa_type":                    "IMMIGRATION_STATUS",
            "citizenship":                  "NRP",
            "ethnicity":                    "NRP",
            "gender":                       "NRP",
            "disability_status":            "DISABILITY_ACCOMMODATION",
            "veteran_status":               "VETERAN_STATUS",
            "essay":                        None,
            "personal_statement":           None,
            "counselor_notes":              None,
            "interview_notes":              None,
        },
        "default_mode": "mask",
    },
    "starfish_early_alert": {
        "description": "EAB Starfish early alert — student success case notes and flag records",
        "field_hints": {
            "student.first_name":           "PERSON",
            "student.last_name":            "PERSON",
            "student.email":                "EMAIL_ADDRESS",
            "student.id":                   "STUDENT_ID",
            "advisor.name":                 "PERSON",
            "advisor.email":                "EMAIL_ADDRESS",
            "flag_reason":                  None,
            "note_text":                    None,
            "case_note":                    None,
            "referral_note":                None,
            "intervention_note":            None,
            "tracking_item_name":           None,
        },
        "default_mode": "mask",
    },
    "canvas_lms": {
        "description": "Instructure Canvas LMS — user, enrollment, and submission record fields",
        "field_hints": {
            "sis_user_id":                  "STUDENT_ID",
            "sis_login_id":                 "DOANE_EMAIL",
            "login_id":                     "EMAIL_ADDRESS",
            "name":                         "PERSON",
            "sortable_name":                "PERSON",
            "short_name":                   "PERSON",
            "email":                        "EMAIL_ADDRESS",
            "submission_comments":          None,
            "body":                         None,
            "comment":                      None,
            "message":                      None,
            "bio":                          None,
        },
        "default_mode": "mask",
    },
    "microsoft_graph": {
        "description": "Microsoft Graph API — Azure AD user and Teams message fields",
        "field_hints": {
            "userPrincipalName":            "EMAIL_ADDRESS",
            "mail":                         "EMAIL_ADDRESS",
            "displayName":                  "PERSON",
            "givenName":                    "PERSON",
            "surname":                      "PERSON",
            "mobilePhone":                  "PHONE_NUMBER",
            "businessPhones":               "PHONE_NUMBER",
            "streetAddress":                "LOCATION",
            "city":                         "LOCATION",
            "postalCode":                   "LOCATION",
            "employeeId":                   "COLLEAGUE_ID",
            "onPremisesSamAccountName":     "COLLEAGUE_ID",
            "body.content":                 None,
            "content":                      None,
            "subject":                      None,
        },
        "default_mode": "mask",
    },
}


# ---------------------------------------------------------------------------
# Config container
# ---------------------------------------------------------------------------

@dataclass
class PiiServiceConfig:
    entity_thresholds: dict[str, float] = field(default_factory=dict)
    custom_patterns: list[dict] = field(default_factory=list)
    schema_profiles: dict[str, dict] = field(default_factory=dict)
    pseudo_pools: dict[str, list] = field(default_factory=dict)

    def get_threshold(self, entity_type: str, default: float) -> float:
        return self.entity_thresholds.get(entity_type, default)

    def get_schema_profile(self, name: str) -> Optional[dict]:
        if name in BUILT_IN_SCHEMA_PROFILES:
            return BUILT_IN_SCHEMA_PROFILES[name]
        return self.schema_profiles.get(name)

    def all_schema_profiles(self) -> dict[str, dict]:
        merged = dict(BUILT_IN_SCHEMA_PROFILES)
        merged.update(self.schema_profiles)
        return merged


def load_config() -> PiiServiceConfig:
    """
    Load configuration from PII_CONFIG_FILE env var (path to JSON).
    If not set or file not found, returns default empty config.
    """
    config_path = os.getenv("PII_CONFIG_FILE", "").strip()
    if not config_path:
        return PiiServiceConfig()

    path = Path(config_path)
    if not path.exists():
        logger.warning("PII_CONFIG_FILE '%s' not found — using defaults", config_path)
        return PiiServiceConfig()

    try:
        with path.open() as f:
            data: dict[str, Any] = json.load(f)
        cfg = PiiServiceConfig(
            entity_thresholds=data.get("entity_thresholds", {}),
            custom_patterns=data.get("custom_patterns", []),
            schema_profiles=data.get("schema_profiles", {}),
            pseudo_pools=data.get("pseudo_pools", {}),
        )
        logger.info(
            "Config loaded from '%s': %d entity thresholds, %d custom patterns, %d profiles",
            config_path,
            len(cfg.entity_thresholds),
            len(cfg.custom_patterns),
            len(cfg.schema_profiles),
        )
        return cfg
    except Exception as exc:
        logger.error("Failed to load PII_CONFIG_FILE '%s': %s — using defaults", config_path, exc)
        return PiiServiceConfig()


# Singleton — loaded once at import time
_config: Optional[PiiServiceConfig] = None


def get_config() -> PiiServiceConfig:
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reload_config() -> PiiServiceConfig:
    """Force reload from disk. Useful for tests or hot-reload scenarios."""
    global _config
    _config = load_config()
    return _config
