import json
from jsonschema import validate

# Define schemas for different credential types
CREDENTIAL_SCHEMAS = {
    "mVAC": {
        "type": "object",
        "properties": {
            "voterID": {"type": "string"},
            "electionAuthority": {"type": "string"},
            "expirationDate": {"type": "string", "format": "date"}
        },
        "required": ["voterID", "electionAuthority", "expirationDate"]
    },
    "mDL": {
        "type": "object",
        "properties": {
            "licenseNumber": {"type": "string"},
            "fullName": {"type": "string"},
            "dateOfBirth": {"type": "string", "format": "date"},
            "expirationDate": {"type": "string", "format": "date"},
            "licenseClass": {"type": "string"}
        },
        "required": ["licenseNumber", "fullName", "dateOfBirth", "expirationDate", "licenseClass"]
    },
    "eID": {
        "type": "object",
        "properties": {
            "idNumber": {"type": "string"},
            "fullName": {"type": "string"},
            "dateOfBirth": {"type": "string", "format": "date"},
            "nationality": {"type": "string"},
            "issuingAuthority": {"type": "string"}
        },
        "required": ["idNumber", "fullName", "dateOfBirth", "nationality", "issuingAuthority"]
    },
    "EducationCredential": {
        "type": "object",
        "properties": {
            "degree": {"type": "string"},
            "institution": {"type": "string"},
            "graduationYear": {"type": "integer"}
        },
        "required": ["degree", "institution", "graduationYear"]
    },
    "EmploymentCredential": {
        "type": "object",
        "properties": {
            "jobTitle": {"type": "string"},
            "employer": {"type": "string"},
            "startDate": {"type": "string", "format": "date"},
            "endDate": {"type": "string", "format": "date"}
        },
        "required": ["jobTitle", "employer", "startDate"]
    },
    "HealthCredential": {
        "type": "object",
        "properties": {
            "condition": {"type": "string"},
            "diagnosis": {"type": "string"},
            "treatmentDate": {"type": "string", "format": "date"}
        },
        "required": ["condition", "diagnosis", "treatmentDate"]
    }
}

def validate_credential_subject(credential_type, subject_data):
    if credential_type not in CREDENTIAL_SCHEMAS:
        raise ValueError(f"Unsupported credential type: {credential_type}")
    
    try:
        validate(instance=subject_data, schema=CREDENTIAL_SCHEMAS[credential_type])
        return True
    except Exception as e:
        print(f"Validation error: {str(e)}")
        return False

def get_credential_types():
    return list(CREDENTIAL_SCHEMAS.keys())
