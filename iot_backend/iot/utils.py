import requests
import urllib.parse
from .models import Threat, Iot_Device
import requests
import re
import json


def get_friendly_attack_name(cve_data):
    """
    Use LLaMA 3 to generate a friendly name for a CVE based on its description and CWE info

    Args:
        cve_data: The CVE data dictionary from NVD API

    Returns:
        str: A friendly name for the attack
    """
    # Extract CWE information
    weaknesses = cve_data.get('weaknesses', [])
    cwe_descriptions = []
    for weakness in weaknesses:
        for desc in weakness.get('description', []):
            if desc.get('lang') == 'en' and desc.get('value', '').startswith('CWE-'):
                cwe_descriptions.append(desc.get('value'))

    # Extract English description
    descriptions = cve_data.get('descriptions', [])
    description = next((d.get('value', '')
                       for d in descriptions if d.get('lang') == 'en'), '')

    # Create a prompt for LLaMA 3
    prompt = f"""Based on the following CVE information, provide a short (1-3 words), human-friendly attack type name:

CVE ID: {cve_data.get('id', 'Unknown')}
CWE Information: {', '.join(cwe_descriptions) if cwe_descriptions else 'Not specified'}
Description: {description}

Respond with ONLY the attack type name like: Overflow, Memory, Corruption, Sql Injection, XSS, Directory Traversal, File Inclusion, CSRF, XXE, SSRF, Open Redirect, Input Validation, Code Execution, Bypass, Privilege Escalation, Denial of Service, Information Leak."""

    # Call LLaMA 3 API (you'll need to replace this with your actual LLaMA 3 API call)
    try:
        # Example integration with a local LLaMA API
        # Replace with your actual implementation
        response = call_llama_api(prompt)
        attack_name = clean_attack_name(response)
        return attack_name
    except Exception as e:
        # Fallback: use regex to extract common attack patterns
        print(f"LLaMA API error: {str(e)}, falling back to pattern matching")
        return extract_attack_pattern(cwe_descriptions, description)


def call_llama_api(prompt):
    """
    Call LLaMA 3 API
    """

    # Example for a local LLaMA API endpoint
    api_url = "http://localhost:11434/api/chat"

    try:
        data = {
            "model": "llama3",
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "stream": False
        }
        headers = {
            "Content-Type": "application/json"
        }

        response = requests.post(api_url, headers=headers, json=data)

        if response.status_code == 200:
            return response.json()["message"]["content"]
        else:
            return f"API Error: {response.status_code}"
    except Exception as e:
        return f"Error calling LLaMA API: {str(e)}"


def clean_attack_name(raw_response):
    """Clean up the LLaMA response to get a concise attack name"""
    # Remove any extra text, quotes, etc.
    cleaned = raw_response.strip().strip('"\'').strip()
    return cleaned


def extract_attack_pattern(cwe_descriptions, description):
    """Fallback method to extract attack pattern from CWE and description"""
    # Common attack patterns to look for using the specified categories
    patterns = {
        # Overflow attacks
        r'(?i)buffer\s*overflow|(?i)stack\s*overflow|(?i)heap\s*overflow|(?i)\boverflow\b': 'Overflow',
        # Memory corruption
        r'(?i)memory\s*corruption|(?i)use\s*after\s*free|(?i)double\s*free|(?i)null\s*pointer': 'Memory Corruption',
        # SQL Injection
        r'(?i)sql\s*injection|(?i)sqli': 'SQL Injection',
        # Cross-site scripting
        r'(?i)cross[\s-]*site\s*scripting|(?i)XSS': 'XSS',
        # Directory traversal
        r'(?i)directory\s*traversal|(?i)path\s*traversal|(?i)\.\.\/': 'Directory Traversal',
        # File inclusion
        r'(?i)file\s*inclusion|(?i)remote\s*file\s*inclusion|(?i)local\s*file\s*inclusion|(?i)RFI|(?i)LFI': 'File Inclusion',
        # CSRF
        r'(?i)CSRF|(?i)cross[\s-]*site\s*request\s*forgery': 'CSRF',
        # XXE
        r'(?i)XXE|(?i)XML\s*External\s*Entity': 'XXE',
        # SSRF
        r'(?i)SSRF|(?i)Server\s*Side\s*Request\s*Forgery': 'SSRF',
        # Open redirect
        r'(?i)open\s*redirect': 'Open Redirect',
        # Input validation
        r'(?i)input\s*validation|(?i)improper\s*input|(?i)insufficient\s*validation': 'Input Validation',
        # Code execution
        r'(?i)code\s*execution|(?i)command\s*execution|(?i)remote\s*code\s*execution|(?i)RCE|(?i)command\s*injection': 'Code Execution',
        # Bypass
        r'(?i)bypass|(?i)authentication\s*bypass|(?i)authorization\s*bypass': 'Bypass',
        # Privilege escalation
        r'(?i)privilege\s*escalation|(?i)elevation\s*of\s*privilege': 'Privilege Escalation',
        # Denial of service
        r'(?i)denial\s*of\s*service|(?i)DoS': 'Denial of Service',
        # Information leak
        r'(?i)information\s*leak|(?i)information\s*disclosure|(?i)data\s*leak': 'Information Leak'
    }

    # Check CWE descriptions first
    for cwe in cwe_descriptions:
        for pattern, name in patterns.items():
            if re.search(pattern, cwe):
                return name

    # Then check the main description
    for pattern, name in patterns.items():
        if re.search(pattern, description):
            return name

    # Get CWE number as fallback
    cwe_match = re.search(r'CWE-(\d+)', ' '.join(cwe_descriptions))
    if cwe_match:
        return f"CWE-{cwe_match.group(1)}"

    return "Security Vulnerability"


def get_threat_level_from_cvss(score):
    """Map CVSS score to threat level"""
    if score is None:
        return "Low"
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    else:
        return "Low"


def search_vulnerabilities_for_device(device_id):
    """
    Search for vulnerabilities for a given device and create Threat objects
    """
    try:
        # Get the device
        device = Iot_Device.objects.get(id=device_id)

        # Encode the device name for URL
        encoded_name = urllib.parse.quote(device.name)

        # Query the NVD API
        api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_name}"
        response = requests.get(api_url)

        if response.status_code != 200:
            print(f"Error fetching vulnerabilities: {response.status_code}")
            return

        data = response.json()
        total_results = data.get('totalResults', 0)
        vulnerabilities = data.get('vulnerabilities', [])

        # Limit to 50 vulnerabilities if there are more
        if total_results > 50:
            print(
                f"Found {total_results} vulnerabilities for {device.name}, limiting to 50 to avoid overload.")
            vulnerabilities = vulnerabilities[:50]

        # Create threats for each vulnerability
        for vuln in vulnerabilities:
            cve_data = vuln.get('cve', {})
            cve_id = cve_data.get('id', 'Unknown CVE')

            # Get description
            descriptions = cve_data.get('descriptions', [])
            description = next((d.get('value', '') for d in descriptions if d.get(
                'lang') == 'en'), 'No description available')

            # Get CVSS score for threat level determination
            metrics = cve_data.get('metrics', {})
            cvss_score = None

            # Try to get CVSS v3.1 score first, then v3.0, then v2.0
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore')
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore')
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore')

            threat_level = get_threat_level_from_cvss(cvss_score)

            # Get friendly attack name - try LLaMA first, then pattern matching
            try:
                friendly_attack_name = get_friendly_attack_name(cve_data)
            except Exception:
                friendly_attack_name = extract_attack_pattern(
                    [d.get('value', '') for weakness in cve_data.get('weaknesses', [])
                     for d in weakness.get('description', []) if d.get('lang') == 'en'],
                    description
                )

            # Save CVE ID separately
            threat, created = Threat.objects.get_or_create(
                CVE_ID=cve_id,
                defaults={
                    'attack_Name': friendly_attack_name,
                    'threat_Level': threat_level,
                    # Truncate if needed
                    'description': description[:700] if description else None
                }
            )

            # Link to the device
            threat.devices.add(device)

            print(
                f"{'Created' if created else 'Updated'} threat: {cve_id} ({friendly_attack_name}) with level {threat_level}")

            # Generate threat details for each category
            from .models import Threat_Info_Category, Threat_Detail

            categories = Threat_Info_Category.objects.all()
            for category in categories:
                # Check if we already have a threat detail for this threat and category
                existing_detail = Threat_Detail.objects.filter(
                    Threat=threat,
                    threat_Info_Category=category
                ).first()

                if not existing_detail:
                    # Generate the threat detail content
                    details = generate_threat_detail(threat, device, category)

                    # Create the threat detail
                    threat_detail = Threat_Detail.objects.create(
                        Threat=threat,
                        threat_Info_Category=category,
                        # ai_summary= ai_summary,
                        details=details
                    )

                    print(
                        f"Created threat detail for {threat.CVE_ID}: {category.topic}")

    except Exception as e:
        print(f"Error searching vulnerabilities: {str(e)}")


def generate_threat_detail(threat, device, category):
    """
    Generate threat detail content based on the threat, device, and category topic

    Args:
        threat: The Threat object
        device: The Iot_Device object
        category: The Threat_Info_Category object

    Returns:
        tuple: (ai_summary, details)
    """
    from .models import Threat_Info_Category

    # Build a prompt based on the category
    prompt = f"""Based on the following vulnerability information, identify {category.description}:
        CVE ID: {threat.CVE_ID if threat.CVE_ID else "Unknown"}
    Attack Name: {threat.attack_Name}
    Device: {device.name} ({device.description})
    Threat Level: {threat.threat_Level}
    Description: {threat.description}

    {category.prompt}
    """
    # Call LLaMA API to generate the content
    try:
        response = call_llama_api(prompt)
        return response
    except Exception as e:
        print(f"Error generating threat detail: {str(e)}")
        return f"Error generating {category.topic} details", f"Failed to generate {category.topic} details: {str(e)}"
